// Package capability: narrow capability-accumulation accounting.
// Default NoopEvaluator; opt-in via config flag. Deterministic, stdlib-only.
//
// normalize.go — canonical identity/normalization helpers (path, host, CIDR,
// executable), workspace containment, declared-authority validation, and the
// strict RFC 1123 hostname rule.
package capability

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

func ValidateAuthority(da DeclaredAuthority) error {
	if da.Target == "" {
		return fmt.Errorf("%w: missing declared target", ErrInvalidStep)
	}
	if da.WorkspaceRoot == "" {
		return fmt.Errorf("%w: missing workspace root", ErrInvalidStep)
	}
	for i, p := range da.Network {
		if !p.IsValid() {
			return fmt.Errorf("%w: declared network %d invalid", ErrInvalidStep, i)
		}
		if p.Addr() != p.Masked().Addr() {
			return fmt.Errorf("%w: declared network %s has host bits", ErrInvalidStep, p.String())
		}
	}
	if da.Host != "" {
		if _, err := CanonicalHostIsValid(da.Host); err != nil {
			return fmt.Errorf("%w: malformed declared host %q", ErrInvalidStep, da.Host)
		}
	}
	for _, exe := range da.DeclaredExecutables {
		if exe == "" || exe == "." || exe == ".." || CanonicalExecutable(exe) != exe {
			return fmt.Errorf("%w: malformed declared executable %q", ErrInvalidStep, exe)
		}
	}
	return nil
}

// normalizeDeclaredAuthority returns the canonical form of a validated
// declared authority: Host lowercased with trailing dot stripped,
// DeclaredExecutables reduced to canonical base names, Network CIDRs
// masked, and WorkspaceRoot cleaned. Attribution and the sealed receipt
// use the normalized form so receipt identity is deterministic
// regardless of the original spelling (reviewer run 179). It MUST be
// called only after ValidateAuthority succeeds (no error return).
func normalizeDeclaredAuthority(da DeclaredAuthority) DeclaredAuthority {
	if da.Host != "" {
		da.Host = CanonicalHost(da.Host)
	}
	exes := make([]string, 0, len(da.DeclaredExecutables))
	for _, e := range da.DeclaredExecutables {
		exes = append(exes, CanonicalExecutable(e))
	}
	da.DeclaredExecutables = exes
	nets := make([]netip.Prefix, 0, len(da.Network))
	for _, p := range da.Network {
		nets = append(nets, p.Masked())
	}
	da.Network = nets
	if da.WorkspaceRoot != "" {
		da.WorkspaceRoot = filepath.Clean(da.WorkspaceRoot)
	}
	return da
}

// CanonicalPath returns the canonical absolute path and verifies containment
// under workspaceRoot. Unresolvable paths on boundary requests fail closed
// (caller decides via RequireExists).
func CanonicalPath(p, workspaceRoot string, requireExists bool) (string, error) {
	if p == "" || workspaceRoot == "" {
		return "", fmt.Errorf("%w: empty path or workspace root", ErrInvalidStep)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("%w: abs: %v", ErrInvalidStep, err)
	}
	abs = filepath.Clean(abs)
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", fmt.Errorf("%w: abs root: %v", ErrInvalidStep, err)
	}
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", fmt.Errorf("%w: rel: %v", ErrInvalidStep, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path outside workspace: %s", ErrInvalidStep, abs)
	}
	if requireExists {
		// Resolve the deepest existing ancestor of abs (per-component walk),
		// then re-attach the residual components lexically. This catches
		// symlink escapes through existing ancestors even when the final
		// target does not exist yet (a mediated write being created). It is
		// the same per-component discipline as the audit path-binding work.
		resolved, residual, err := resolveExistingAncestors(abs)
		if err != nil {
			return "", fmt.Errorf("%w: resolve %s: %v", ErrInvalidStep, abs, err)
		}
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			return "", fmt.Errorf("%w: resolve root: %v", ErrInvalidStep, err)
		}
		joined := filepath.Join(append([]string{resolved}, residual...)...)
		rel2, err := filepath.Rel(resolvedRoot, joined)
		if err != nil {
			return "", fmt.Errorf("%w: rel resolved: %v", ErrInvalidStep, err)
		}
		if rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("%w: symlink escape outside workspace: %s", ErrInvalidStep, joined)
		}
		return joined, nil
	}
	return abs, nil
}

// PathOutsideWorkspace reports whether p canonically resolves OUTSIDE ws.
// It returns (true, nil) when containment is deterministically proven
// outside (lexical or resolved-symlink escape), (false, nil) when provably
// inside, and an error when the path cannot be resolved at all (no existing
// ancestor) — a fail-closed evaluator error, never a boundary claim.
//
// Rev 15 (reviewer run 200): the workspace root is resolved BEFORE any
// lexical-outside classification. A missing/nonexistent workspace root is an
// evaluator error (fail closed → PAUSE), never an ordinary E5 classification
// of a lexically-outside path. The previous order returned (true, nil) for
// p=/etc/passwd under ws=/does-not-exist-review-root before the root was
// ever resolved, letting an explicit file_access outside reach ordinary E5
// instead of evaluator_error.
func PathOutsideWorkspace(p, ws string) (bool, error) {
	if p == "" || ws == "" {
		return false, fmt.Errorf("%w: empty path or workspace root", ErrInvalidStep)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false, fmt.Errorf("%w: abs: %v", ErrInvalidStep, err)
	}
	abs = filepath.Clean(abs)
	root, err := filepath.Abs(ws)
	if err != nil {
		return false, fmt.Errorf("%w: abs root: %v", ErrInvalidStep, err)
	}
	root = filepath.Clean(root)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, fmt.Errorf("%w: resolve root: %v", ErrInvalidStep, err)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false, fmt.Errorf("%w: rel: %v", ErrInvalidStep, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true, nil // lexically outside (root already proven resolvable)
	}
	resolved, residual, err := resolveExistingAncestors(abs)
	if err != nil {
		return false, err // no existing ancestor → evaluator error
	}
	joined := filepath.Join(append([]string{resolved}, residual...)...)
	rel2, err := filepath.Rel(resolvedRoot, joined)
	if err != nil {
		return false, fmt.Errorf("%w: rel resolved: %v", ErrInvalidStep, err)
	}
	if rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return true, nil // resolved symlink escape → outside
	}
	return false, nil
}

// resolveExistingAncestors walks abs upward to the deepest existing ancestor,
// EvalSymlinks' it, and returns the resolved prefix plus the residual
// components that do not exist yet. If abs itself exists, EvalSymlinks(abs)
// returns it with an empty residual.
func resolveExistingAncestors(abs string) (string, []string, error) {
	cur := abs
	var residual []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if len(residual) == 0 {
				return resolved, nil, nil
			}
			for i, j := 0, len(residual)-1; i < j; i, j = i+1, j-1 {
				residual[i], residual[j] = residual[j], residual[i]
			}
			return resolved, residual, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil, fmt.Errorf("no existing ancestor of %s", abs)
		}
		base := filepath.Base(cur)
		residual = append(residual, base)
		cur = parent
	}
}

// CanonicalExecutable returns filepath.Base(name); path components in exec
// names are stripped so only the base name is matched against the declared
// set.
func CanonicalExecutable(name string) string {
	return filepath.Base(name)
}

// CanonicalHost lowercases and strips a single trailing dot.
func CanonicalHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// CanonicalCIDR parses and normalizes a CIDR, rejecting host bits.
func CanonicalCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: cidr: %v", ErrInvalidStep, err)
	}
	if p.Addr() != p.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("%w: cidr has host bits: %q", ErrInvalidStep, s)
	}
	return p.Masked(), nil
}
func CanonicalHostIsValid(s string) (string, error) {
	h := CanonicalHost(s)
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidStep)
	}
	// Rev 6 (reviewer run 181): IP literals are NOT hostnames. Reject
	// IPv4 (127.0.0.1) and IPv6 (::1, 2001:db8::1) literals before
	// hostname-label validation so an IP cannot enter declared-host
	// identity or host-exec attribution. The structured DestIP field is
	// the only channel for IP destinations.
	if ip, err := netip.ParseAddr(h); err == nil {
		return "", fmt.Errorf("%w: IP literal %q is not a hostname", ErrInvalidStep, ip.String())
	}
	if len(h) > 253 {
		return "", fmt.Errorf("%w: host too long %q", ErrInvalidStep, s)
	}
	for _, part := range strings.Split(h, ".") {
		if part == "" {
			return "", fmt.Errorf("%w: empty label in host %q", ErrInvalidStep, s)
		}
		if len(part) > 63 {
			return "", fmt.Errorf("%w: label too long in host %q", ErrInvalidStep, s)
		}
		if part[0] == '-' || part[len(part)-1] == '-' {
			return "", fmt.Errorf("%w: label starts/ends with hyphen in host %q", ErrInvalidStep, s)
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("%w: malformed host %q", ErrInvalidStep, s)
			}
		}
	}
	return h, nil
}
