// Package capability probes the Rev 14 adapter contract surface: the exact
// types, constants, canonicalization helpers, receipt hashing, the stateful
// chain evaluator, the fixed capability lattice with per-session state, and
// the E5-only pause predicate, as specified in the design contract §7.
//
// Rev 14 changes vs Rev 13 (Mayur operator decision, run 197 — STOP the
// design loop, eliminate the parent condition):
//   - The empty-Effect file-boundary derivation is REMOVED ENTIRELY.
//     ExtractSignals emits boundary.request_file_outside_workspace ONLY
//     inside case EffectFileAccess (explicit structured effect).
//   - deriveEffectKind derives ONLY host_exec and net_egress. A
//     file-outside observation (structured or pre-populated) WITHOUT an
//     explicit Effect is UNTYPED → evaluator error → PAUSE (Eval's untyped
//     guard; never ALLOW, never silent).
//   - Non-file effects NEVER trigger file-boundary signals (row-8 source
//     confusion is structurally impossible — there is no fallback scan).
//   - bindDerivedTarget no longer has a file_access case; Eval's
//     pre-attribution path-resolution guard is removed (no derived file
//     scan to resolve). PathOutsideWorkspace still governs explicit
//     file_access attribution and row-8 emission.
//
// Rev 4 changes vs Rev 3 (independent review run 177 findings):
//   - Host-exec attribution uses the STRUCTURED Step.Executable, and the raw
//     EffectTarget must agree with it (canonical base names); a missing
//     structured executable is an error (fail closed).
//   - Net-egress REQUIRES the raw EffectTarget and exact raw/structured
//     agreement (DestIP equal address / DestHost equal canonical hostname);
//     an empty raw target with a valid DestIP is an error (fail closed).
//   - Fixed capability lattice with per-session held state: baseline
//     read_sandbox_mem, evidence-to-delta reduction (confirmedDelta),
//     unionLattice accumulation, ObservedCapability, and a provisional
//     declared-primitive representation (CDR D1/CD-3 semantics).
//   - ExtractSignals emits boundary.request_file_outside_workspace ONLY
//     when containment is deterministically proven outside; an in-workspace
//     path never emits it. Build-artifact detection no longer requires a
//     Path; a typed ArtifactMagic (ELF/PE) fingerprint is a first-class
//     observation.
//   - ValidateAuthority validates/canonicalizes declared Host and
//     DeclaredExecutables (malformed → error → PAUSE).
//   - Receipt schema matches CDR exactly: nested EnvelopeState objects and
//     the provisional_capability field.
//
// Rev 5 changes vs Rev 4 (independent review run 179 findings):
//   - Host-exec partial-authority sets are defined: with a declared
//     executable set but NO declared host, host membership cannot be
//     established → E5 (never ALLOW). With a declared host, the observed
//     DestHost is required and must equal it. All partial-set combinations
//     produce E5 or evaluator error; empty optional sets keep the shipped
//     unconditional E5 default.
//   - File access uses the STRUCTURED Step.Path as the canonical field when
//     present; the raw EffectTarget must agree (same containment verdict and
//     same canonical path when inside). Disagreement → error → PAUSE.
//   - Decode is strict JSONL: exactly one object plus optional trailing
//     newline; no leading/trailing whitespace, no trailing objects/garbage,
//     no duplicate keys; re-encoding is byte-identical.
//   - CanonicalHostIsValid is strict RFC 1123: label length ≤ 63, total ≤
//     253, no leading/trailing hyphens, no empty labels, trailing-dot
//     normalization.
//   - Eval normalizes the declared authority (host, executables, CIDRs)
//     before attribution and receipt construction so receipt identity is
//     deterministic regardless of the original spelling.
//
// This file is the evaluation/signal/lattice slice of the production split:
// EffectAttributable, ExtractSignals and the fingerprint matchers,
// confirmedDelta/bindDerivedTarget/deriveEffectKind, and the lattice helpers.
// See evaluator.go (interface + chain), receipt.go (receipts), normalize.go
// (canonical identity).

package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func EffectAttributable(step Step) (bool, error) {
	// A populated-but-malformed DestHost is an evaluator error (fail
	// closed), independent of Effect kind — never ALLOW and never ordinary
	// E5. Valid DestHost/DestIP is handled below; this only rejects
	// unparseable observations (Codex P1 / host_exec Rev 8 hoist).
	if _, err := structuredDestination(step); err != nil {
		return false, err
	}
	da := step.Declared
	switch step.Effect {
	case EffectHostExec:
		// The STRUCTURED executable observation is the canonical field for
		// attribution; the raw EffectTarget must agree with it. A missing or
		// disagreeing structured observation fails closed (reviewer run 177).
		if step.EffectTarget == "" {
			return false, fmt.Errorf("%w: host_exec missing target", ErrInvalidStep)
		}
		if step.Executable == "" {
			return false, fmt.Errorf("%w: host_exec missing structured executable observation", ErrInvalidStep)
		}
		if CanonicalExecutable(step.EffectTarget) != CanonicalExecutable(step.Executable) {
			return false, fmt.Errorf("%w: host_exec target %q != structured executable %q", ErrInvalidStep, step.EffectTarget, step.Executable)
		}
		exe := CanonicalExecutable(step.Executable)
		// Rev 8 (reviewer run 185): ANY populated observed DestHost must be a
		// valid hostname BEFORE the empty/partial-authority E5 branches. A
		// malformed observed host means the proxy fed us an unparseable
		// observation — that is an evaluator error (fail closed), never a
		// plain E5, regardless of whether optional authority is empty or only
		// executables are declared. Missing DestHost is handled per the
		// partial-authority table below (error only when a declared host
		// requires it).
		if step.DestHost != "" {
			if _, err := CanonicalHostIsValid(step.DestHost); err != nil {
				return false, fmt.Errorf("%w: host_exec malformed host observation %q", ErrInvalidStep, step.DestHost)
			}
		}
		// Declared executable set empty = no declared exec = always E5
		// (byte-identical to shipped CD-2, where host_exec is unconditionally
		// outside the envelope).
		if len(da.DeclaredExecutables) == 0 {
			return false, nil
		}
		// Partial-authority table (reviewer run 179). All cases are E5 or
		// evaluator error; no partial set can ALLOW:
		//   declared executable set + declared host:
		//       DestHost required AND == declared host (else error/E5)
		//   declared executable set + NO declared host:
		//       host membership cannot be established → E5 (never ALLOW)
		//   declared host + NO declared executables:
		//       handled above (empty set → E5, shipped default)
		if da.Host == "" {
			// No declared host → host membership is unprovable → E5.
			return false, nil
		}
		// A declared host is set: the observation MUST carry DestHost and it
		// MUST equal the declared host (canonical equality). Missing DestHost
		// is NOT silently treated as in-envelope.
		if step.DestHost == "" {
			return false, fmt.Errorf("%w: host_exec missing host observation", ErrInvalidStep)
		}
		// Rev 7 (reviewer run 183): a MALFORMED observed host is an evaluator
		// error (fail closed), never classified as ordinary E5. The structured
		// DestHost must be a valid hostname before any comparison; a malformed
		// value means the proxy fed us an unparseable observation. (Hoisted to
		// the top of host_exec in Rev 8 so the empty/partial-authority E5
		// branches can never classify a malformed observation as ordinary E5 —
		// reviewer run 185.)
		if CanonicalHost(step.DestHost) != CanonicalHost(da.Host) {
			return false, nil // right exec, wrong host → out-of-envelope
		}
		for _, d := range da.DeclaredExecutables {
			if CanonicalExecutable(d) == exe {
				return true, nil
			}
		}
		return false, nil
	case EffectNetEgress:
		// Fail closed (reviewer run 177): the raw EffectTarget is REQUIRED
		// and must AGREE with the structured DestIP/DestHost. An empty raw
		// target with a valid DestIP is an error; a hostname raw target must
		// canonically equal DestHost. Ambiguity fails closed.
		//
		// Rev 6 (reviewer run 181): when BOTH structured destinations are
		// populated they MUST refer to the same destination. A conflicting
		// DestIP/DestHost pair (e.g. DestIP=10.0.0.7, DestHost=evil.example)
		// is ambiguity at the security boundary even when the raw target
		// matches one of them → evaluator error → PAUSE. The raw target must
		// match the IP branch when DestIP is set and the hostname branch when
		// DestHost is set; both populated → both branches must agree.
		if step.EffectTarget == "" {
			return false, fmt.Errorf("%w: net_egress missing raw target", ErrInvalidStep)
		}
		if ip, err := netip.ParseAddr(step.EffectTarget); err == nil {
			// The raw target must be the SAME address as DestIP when DestIP
			// is set (exact equality, not merely containment).
			if step.DestIP.IsValid() && ip != step.DestIP {
				return false, fmt.Errorf("%w: net_egress target %q does not match DestIP %s", ErrInvalidStep, step.EffectTarget, step.DestIP)
			}
			if step.DestHost != "" {
				// Both structured destinations present: the hostname must be
				// an IP-literal spelling of the same address, or the pair is
				// contradictory → error (reviewer run 181).
				h, err := netip.ParseAddr(step.DestHost)
				if err != nil || h != ip {
					return false, fmt.Errorf("%w: net_egress DestIP %s and DestHost %q disagree", ErrInvalidStep, step.DestIP, step.DestHost)
				}
			}
		} else {
			// Raw target is a hostname: DestIP must NOT be set (an IP cannot
			// agree with a hostname — any pairing is a contradiction), and
			// the raw target must canonically equal DestHost when set.
			if step.DestIP.IsValid() {
				return false, fmt.Errorf("%w: net_egress hostname target %q conflicts with DestIP %s", ErrInvalidStep, step.EffectTarget, step.DestIP)
			}
			if step.DestHost != "" {
				h, err := CanonicalHostIsValid(step.EffectTarget)
				if err != nil {
					return false, fmt.Errorf("%w: net_egress malformed target %q", ErrInvalidStep, step.EffectTarget)
				}
				if h != CanonicalHost(step.DestHost) {
					return false, fmt.Errorf("%w: net_egress target %q does not match DestHost %q", ErrInvalidStep, step.EffectTarget, step.DestHost)
				}
			} else if _, err := CanonicalHostIsValid(step.EffectTarget); err != nil {
				return false, fmt.Errorf("%w: net_egress malformed target %q", ErrInvalidStep, step.EffectTarget)
			}
		}
		if len(da.Network) == 0 {
			return false, nil // no declared network = no declared egress = always E5
		}
		if step.DestIP.IsValid() {
			for _, p := range da.Network {
				if p.Contains(step.DestIP) {
					return true, nil
				}
			}
			return false, nil
		}
		if step.DestHost != "" {
			// No DNS in the decision path (deterministic): an undeclared
			// hostname is out-of-envelope.
			return false, nil
		}
		// Raw-only target parsed as an IP above; use it for containment.
		if ip, err := netip.ParseAddr(step.EffectTarget); err == nil {
			for _, p := range da.Network {
				if p.Contains(ip) {
					return true, nil
				}
			}
			return false, nil
		}
		return false, nil // raw hostname: out-of-envelope (no DNS)
	case EffectFileAccess:
		if step.EffectTarget == "" {
			return false, fmt.Errorf("%w: file_access missing target", ErrInvalidStep)
		}
		if da.WorkspaceRoot == "" {
			return false, fmt.Errorf("%w: missing workspace root", ErrInvalidStep)
		}
		// Canonical structured field (reviewer run 179): when Step.Path is
		// present it is the authoritative path for containment; the raw
		// EffectTarget must AGREE with it — same containment verdict and,
		// when inside, the same canonical path. A disagreement is ambiguity
		// at the security boundary → evaluator error → PAUSE.
		if step.Path != "" {
			rawOutside, err := PathOutsideWorkspace(step.EffectTarget, da.WorkspaceRoot)
			if err != nil {
				return false, err
			}
			pathOutside, err := PathOutsideWorkspace(step.Path, da.WorkspaceRoot)
			if err != nil {
				return false, err
			}
			if rawOutside != pathOutside {
				return false, fmt.Errorf("%w: file_access raw target %q and structured path %q disagree on containment", ErrInvalidStep, step.EffectTarget, step.Path)
			}
			if !pathOutside {
				rawCanon, err := CanonicalPath(step.EffectTarget, da.WorkspaceRoot, false)
				if err != nil {
					return false, err
				}
				pathCanon, err := CanonicalPath(step.Path, da.WorkspaceRoot, false)
				if err != nil {
					return false, err
				}
				if rawCanon != pathCanon {
					return false, fmt.Errorf("%w: file_access raw target %q and structured path %q differ", ErrInvalidStep, step.EffectTarget, step.Path)
				}
			}
			if pathOutside {
				return false, nil // E5: structured path outside workspace → PAUSE effect_outside
			}
			return true, nil
		}
		// No structured Path: the raw EffectTarget alone determines
		// containment (deterministic; the proxy mirrors the tool arg).
		outside, err := PathOutsideWorkspace(step.EffectTarget, da.WorkspaceRoot)
		if err != nil {
			return false, err // unresolvable → evaluator error → PAUSE
		}
		if outside {
			return false, nil // E5: outside workspace → PAUSE effect_outside
		}
		return true, nil
	case EffectCanaryAccess:
		return false, nil // definitionally out-of-envelope (CD-2)
	case "":
		// No effect on this step: non-boundary signal. Never pauses.
		return true, nil
	default:
		return false, fmt.Errorf("%w: unknown effect %q", ErrInvalidStep, step.Effect)
	}
}
func ExtractSignals(step Step) []Signal {
	if len(step.Signals) > 0 {
		return step.Signals
	}
	var out []Signal
	// 1. declared.intent — from the declared authority's intent (context only).
	if step.Declared.Intent != "" {
		out = append(out, Signal{
			Kind:          SignalDeclaredIntent,
			Observation:   "intent: " + step.Declared.Intent,
			EvidenceLevel: EvidenceDeclaredOnly,
			SourceDigest:  digestOf(step.Declared.Intent),
		})
	}
	// 2. artifact.poc_created from mediated file-write args (path + extension)
	//    OR an args blob path with a PoC extension.
	blob := argsBlob(step)
	if p := step.Path; p != "" {
		switch strings.ToLower(filepath.Ext(p)) {
		case ".js", ".py", ".wasm", ".sh", ".c":
			out = append(out, Signal{
				Kind:          SignalArtifactPocCreated,
				Observation:   "wrote " + filepath.Base(p),
				EvidenceLevel: EvidenceArtifact,
				SourceDigest:  digestOf(p),
			})
		}
	}
	if !hasSignal(out, SignalArtifactPocCreated) {
		if p := pocPathFromArgs(blob); p != "" {
			out = append(out, Signal{
				Kind:          SignalArtifactPocCreated,
				Observation:   "wrote " + filepath.Base(p),
				EvidenceLevel: EvidenceArtifact,
				SourceDigest:  digestOf(p),
			})
		}
	}
	// 3. artifact.build_artifact — from a build tool observation (Tool or
	//    Args) OR a typed mediated byte fingerprint (ELF/PE magic),
	//    independent of Path.
	if isBuildTool(step.Tool) || isBuildToolArgs(step) {
		obs := "build tool " + step.Tool
		if !isBuildTool(step.Tool) {
			obs = "build tool in args"
		}
		out = append(out, Signal{
			Kind:          SignalArtifactBuildArtifact,
			Observation:   obs,
			EvidenceLevel: EvidenceArtifact,
			SourceDigest:  digestOf(step.Tool),
		})
	}
	switch step.ArtifactMagic {
	case "ELF", "PE":
		out = append(out, Signal{
			Kind:          SignalArtifactBuildArtifact,
			Observation:   "artifact magic " + step.ArtifactMagic,
			EvidenceLevel: EvidenceArtifact,
			SourceDigest:  digestOf(step.ArtifactMagic),
		})
	}
	// 4-5. runtime markers from mediated result strings AND args.
	markerScan := step.Result
	if blob != "" {
		markerScan += "\n" + blob
	}
	for _, m := range matchMarkers(markerScan, memoryCorruptionMarkers) {
		out = append(out, Signal{
			Kind:          SignalRuntimeMemoryCorruption,
			Observation:   m,
			EvidenceLevel: EvidenceRuntimeMarker,
			SourceDigest:  digestOf(m),
		})
	}
	for _, m := range matchMarkers(markerScan, sandboxEscapeMarkers) {
		out = append(out, Signal{
			Kind:          SignalRuntimeSandboxEscape,
			Observation:   m,
			EvidenceLevel: EvidenceRuntimeMarker,
			SourceDigest:  digestOf(m),
		})
	}
	// 6-8. boundary kinds — from structured Effect fields OR mediated
	//    tool/argument surfaces (Rev 9).
	switch step.Effect {
	case EffectHostExec:
		out = append(out, Signal{
			Kind:          SignalBoundaryHostExec,
			Observation:   "host exec " + step.Executable,
			EvidenceLevel: EvidenceBoundaryRequest,
			SourceDigest:  digestOf(step.Executable),
		})
	case EffectNetEgress:
		out = append(out, Signal{
			Kind:          SignalBoundaryEgress,
			Observation:   "egress to " + step.EffectTarget,
			EvidenceLevel: EvidenceBoundaryRequest,
			SourceDigest:  digestOf(step.EffectTarget),
		})
	case EffectFileAccess:
		// Rev 6 (reviewer run 181): when Step.Path is present it is the
		// CANONICAL file field (same rule as EffectAttributable). The raw
		// EffectTarget is only used when no structured path exists. The
		// signal is emitted ONLY when containment is deterministically
		// proven outside; an unresolvable path is the evaluator's
		// fail-closed error, never a boundary claim.
		filePath := step.EffectTarget
		if step.Path != "" {
			filePath = step.Path
		}
		if outside, err := PathOutsideWorkspace(filePath, step.Declared.WorkspaceRoot); err == nil && outside {
			out = append(out, Signal{
				Kind:          SignalBoundaryFileOutside,
				Observation:   "file " + filePath,
				EvidenceLevel: EvidenceBoundaryRequest,
				SourceDigest:  digestOf(filePath),
			})
		}
	}
	// Rev 14 (Mayur operator decision, run 197): the empty-Effect
	// file-boundary derivation is REMOVED ENTIRELY. A file-boundary
	// observation WITHOUT an explicit structured Effect is UNTYPED and
	// FAILS CLOSED (evaluator error → PAUSE) in Eval; ExtractSignals never
	// derives row 8 from an empty-Effect surface. Row 8 is emitted ONLY
	// inside case EffectFileAccess above (explicit file_access effect with a
	// deterministically proven outside path). This eliminates the parent
	// condition behind reviewer runs 194 and 196 (empty-Effect file-boundary
	// derivation): there is no derived file scan to fail open on an
	// unresolvable workspace root, and no fallback to false-signal explicit
	// non-file effects. Non-file effects NEVER trigger file-boundary
	// signals.
	// Mediated tool/argument surfaces for boundary signals (Rev 9): emit the
	// boundary signal when the TOOL CALL itself (name or args) requests it,
	// even if the structured Effect was not populated. Dedup against the
	// structured emission above.
	if !hasSignal(out, SignalBoundaryHostExec) && hostExecFromArgs(step, blob) {
		out = append(out, Signal{
			Kind:          SignalBoundaryHostExec,
			Observation:   "host exec " + step.Executable,
			EvidenceLevel: EvidenceBoundaryRequest,
			SourceDigest:  digestOf(step.Executable),
		})
	}
	if !hasSignal(out, SignalBoundaryEgress) && egressFromArgs(step, blob) {
		out = append(out, Signal{
			Kind:          SignalBoundaryEgress,
			Observation:   "egress to " + step.EffectTarget,
			EvidenceLevel: EvidenceBoundaryRequest,
			SourceDigest:  digestOf(step.EffectTarget),
		})
	}
	// Rev 10 (reviewer run 189): per-kind dedup across ALL sources. A kind
	// can be produced by several surfaces (structured field, tool name,
	// args, artifact magic, runtime markers); the contract guarantees "the
	// same observation is NEVER double-emitted (dedup per kind)". Keep the
	// FIRST signal of each kind in emission order — deterministic and
	// canonical. (Reviewer reproduced Tool:"gcc" + ArtifactMagic:"ELF"
	// emitting two artifact.build_artifact signals; now collapsed.)
	return dedupByKind(out)
}

// dedupByKind collapses a signal set to the first signal per kind, in
// emission order. Deterministic. Rev 10 (reviewer run 189).
func dedupByKind(signals []Signal) []Signal {
	seen := make(map[string]bool, len(signals))
	out := make([]Signal, 0, len(signals))
	for _, s := range signals {
		if seen[s.Kind] {
			continue
		}
		seen[s.Kind] = true
		out = append(out, s)
	}
	return out
}

// argsBlob serializes the redacted args map into a deterministic blob for
// scanning (sorted keys, NUL-separated). It is used ONLY for content
// scanning (build/host-exec/egress/escape markers); it never carries raw
// secrets into a receipt (the receipt carries only observation strings and
// digests, and the proxy redacts args before constructing Step).
func argsBlob(step Step) string {
	if len(step.Args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(step.Args))
	for k := range step.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(step.Args[k])
		b.WriteByte(0)
	}
	return b.String()
}

// fileSurfacePath returns the canonical mediated file surface of a step:
// the structured Step.Path when present (Rev 5/6 canonical-field rule),
// otherwise the raw EffectTarget. Rev 14: used by Eval's untyped
// fail-closed probe — an empty-Effect step whose mediated file surface is
// outside the workspace (or unresolvable) is an untyped file-boundary
// observation → evaluator error → PAUSE. It is NOT used to emit a row-8
// signal (the empty-Effect file-boundary derivation was removed).
func fileSurfacePath(step Step) string {
	if step.Path != "" {
		return step.Path
	}
	return step.EffectTarget
}

// pocPathFromArgs returns the first PoC-extension path found in the args
// blob, or "" if none. Deterministic: first match in sorted-key order.
func pocPathFromArgs(blob string) string {
	for _, tok := range strings.FieldsFunc(blob, func(r rune) bool { return r == 0 || r == ' ' || r == '=' || r == '"' || r == '\'' || r == ':' }) {
		switch strings.ToLower(filepath.Ext(tok)) {
		case ".js", ".py", ".wasm", ".sh", ".c":
			return tok
		}
	}
	return ""
}

// isBuildToolArgs reports whether the mediated tool-call ARGS surface
// contains a build/exec signature (gcc / go build / clang / cc). It is the
// args-side counterpart of isBuildTool (reviewer run 187). Matching is
// TOKEN-BOUNDARY-AWARE (Rev 11, reviewer run 191): a bare substring match
// would false-positive on "access" (contains "cc"), "clangorous" (contains
// "clang"). A build signature is:
//   - a compiler token exactly equal to gcc/clang/cc (optionally with
//     `-flags` appended), or
//   - the two-token phrase "go build".
//
// Rev 15 (reviewer run 200): the args scan reads ONLY COMMAND-BEARING keys —
// a compiler token in `write_file` `content:"gcc ..."` is benign payload,
// not a mediated build command.
func isBuildToolArgs(step Step) bool {
	for _, v := range commandBearingArgs(step.Args) {
		lv := strings.ToLower(v)
		toks := shellTokens(lv)
		for i, tok := range toks {
			base := compilerTokenBase(tok)
			switch base {
			case "gcc", "clang", "cc":
				return true
			case "go":
				// "go build" phrase: the NEXT token (after this one) is
				// "build". Flags between them (go -flags build) are not a
				// build signature.
				if i+1 < len(toks) && toks[i+1] == "build" {
					return true
				}
			}
		}
	}
	return false
}

// hostExecFromArgs reports whether the mediated tool call (name or args)
// requests host execution: a host_exec/bash/sh tool, or an exec-style
// argument surface. Deterministic and redacted-args-only.
//
// Rev 11 (reviewer run 191): matching is COMMAND-BOUNDARY-AWARE. A bare
// substring match is a false-positive source: "crash", "bashful", "fishing",
// "success" all CONTAIN "sh"/"bash" but are not shell invocations. Only
// canonical surfaces count:
//   - tool name is a canonical host-exec surface (host_exec/bash/sh/
//     /bin/sh//bin/bash/*shell*); or
//   - an arg value under a COMMAND-BEARING KEY contains a command-boundary
//     token that is exactly a canonical shell name (bash, sh, /bin/sh,
//     /bin/bash, host_exec) or an exec-style `-c` invocation of one.
//
// Rev 15 (reviewer run 200): args extraction is COMMAND-BEARING-KEY-AWARE.
// Boundary signals (host_exec/egress/build) are derived from arg values ONLY
// under keys the mediated tool schema designates as command-bearing
// (command/cmd/args/arguments/executable/shell_command). A non-command key —
// e.g. write_file "content" — is ordinary payload/data: `content:"shell"`,
// `content:"bash"`, `content:"curl"` are NOT mediated command executions and
// must not emit boundary signals. Run 191 (substring "crash"/"bashful") and
// run 200 (exact canonical tokens in benign payload) are the SAME failure
// class (scanner treats every arg value as command-bearing); the parent
// condition — scanning non-command arg values at all — is eliminated here.
func hostExecFromArgs(step Step, blob string) bool {
	t := strings.ToLower(step.Tool)
	if isHostExecToolName(t) {
		return true
	}
	if argsContainShellToken(step.Args) {
		return true
	}
	_ = blob // the args blob is scanned via argsContainShellToken on step.Args values
	return false
}

// isHostExecToolName reports whether the TOOL NAME itself is a canonical
// host-exec surface. The tool name is the mediated executable. Rev 11
// (reviewer run 191): EXACT shell-surface names only — "shellac",
// "reshell", "shellfish" are not shell invocations. The visor-shipped
// demo/policy tool `shell_exec` is the same surface as `host_exec`/`shell`:
// a call such as shell_exec({"command":"id"}) executes on the host even
// when the command string contains no canonical shell token.
func isHostExecToolName(t string) bool {
	return isCanonicalShellName(t)
}

// argsContainShellToken reports whether any arg value under a
// COMMAND-BEARING KEY contains a canonical shell invocation at a COMMAND
// BOUNDARY (start of value or after a command separator). Deterministic;
// pure over the redacted args map. A token is a shell invocation when it is
// exactly a canonical shell name or the `sh`/`bash`/`host_exec` of an
// exec-style command (e.g. `sh -c`).
//
// Rev 12 (reviewer run 194): the documented `shell` args surface is part of
// the canonical set — the contract (plan lines 68/564/571-578) lists
// `shell` in host-exec args, and `isHostExecToolName` already accepts the
// `shell` TOOL name. A `shell -c id` args invocation must be observed, not
// silently ALLOWed under empty Effect.
//
// Rev 15 (reviewer run 200): only COMMAND-BEARING keys are scanned. The
// reviewer's exact adversarial cases (`write_file` with `content:"shell"`,
// `content:"bash"`, `content:"curl"`) are benign payload, not mediated
// command executions — under a non-command key they never emit a boundary
// signal. The prior Rev 11/12 negative controls (`crash`, `bashful`,
// `shellac`, ...) remain negative under every key; the new key constraint
// makes them structurally unreachable on payload keys.
func argsContainShellToken(args map[string]string) bool {
	for _, v := range commandBearingArgs(args) {
		lv := strings.ToLower(v)
		for _, tok := range shellTokens(lv) {
			if isCanonicalShellName(tok) {
				return true
			}
		}
	}
	return false
}

// commandBearingArgs returns the arg values under keys the mediated tool
// schema designates as command-bearing, in sorted-key order (deterministic).
// Rev 15 (reviewer run 200): boundary-signal extraction (host_exec/egress/
// build) reads ONLY these keys. Any other key (`content`, `path`, `url`,
// `output`, `body`, ...) is ordinary payload/data and is never scanned for
// command invocations — scanning every arg value was the parent condition
// behind reviewer runs 191 (substring "crash"/"bashful") and 200 (exact
// tokens "shell"/"bash"/"curl" in benign content).
func commandBearingArgs(args map[string]string) []string {
	var out []string
	for _, k := range sortedKeys(args) {
		switch k {
		case "command", "cmd", "args", "arguments", "executable", "shell_command":
			out = append(out, args[k])
		}
	}
	return out
}

// shellTokens splits a lowercased arg value at command boundaries, returning
// the token(s) that directly follow a boundary. Boundaries are whitespace,
// `;`, `&&`, `||`, `|`, `(`, `)`, `{`, `}`, `$`, backtick, `<`, `>` — the
// positions where a shell command could start. This keeps "crash",
// "bashful", "success", "fishing" from matching while preserving
// `bash -c id`, `/bin/sh -c 'ls'`, `$(bash)`, `x; bash -c y`.
func shellTokens(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || isCommandBoundary(s[i]) {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func isCommandBoundary(c byte) bool {
	switch c {
	case ' ', '	', '\n', ';', '&', '|', '(', ')', '{', '}', '$', '`', '<', '>', '=', '\'', '"':
		return true
	}
	return false
}

// canonicalCommandToken reduces a command-boundary token to the executable
// identity the classifiers match: the final path component. Backslash is
// treated as a separator and a trailing ".exe" is stripped. HTTP(S) URLs
// are returned unchanged so a destination is never mistaken for a file
// name. Bare names (bash, curl) are unchanged.
//
// This eliminates the parent of the exact-spelling siblings (/bin/bash vs
// /usr/bin/bash vs ./bash vs bash.exe): classifiers match the frozen
// canonical names against this identity, not against raw path spellings.
func canonicalCommandToken(tok string) string {
	if tok == "" {
		return tok
	}
	if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
		return tok
	}
	n := strings.ReplaceAll(tok, "\\", "/")
	if strings.Contains(n, "/") {
		base := path.Base(n)
		if base != "." && base != "/" {
			n = base
		}
	}
	return strings.TrimSuffix(n, ".exe")
}

// isCanonicalShellName reports whether tok, after path identity reduction,
// is one of the frozen host-exec names. The set is exact and closed:
// interpreters not in this list (python, node, perl, ruby) are out of
// scope, not additional names to enumerate.
func isCanonicalShellName(tok string) bool {
	switch canonicalCommandToken(tok) {
	case "host_exec", "bash", "sh", "shell", "shell_exec":
		return true
	}
	return false
}

// compilerTokenBase is canonicalCommandToken plus the gcc-11 / clang-18
// flag-suffix strip used by build-tool matching.
func compilerTokenBase(tok string) string {
	n := canonicalCommandToken(tok)
	for j := 1; j < len(n); j++ {
		if n[j] == '-' {
			return n[:j]
		}
	}
	return n
}

// structuredDestination reports whether a STRUCTURED DestHost/DestIP field
// is authoritative proof of an egress request, independent of the args
// surface (Codex P1). Distinguishes:
//
//	(true, nil)  — DestIP is valid, or DestHost is a non-empty valid
//	               hostname (or an IP-literal dual-destination spelling)
//	(false, nil) — no structured destination
//	(_, err)     — DestHost is populated but not a valid hostname and not
//	               an IP literal → evaluator error, never ALLOW / never E5
func structuredDestination(step Step) (bool, error) {
	if step.DestHost != "" {
		if _, err := CanonicalHostIsValid(step.DestHost); err != nil {
			// Rev 6 dual-destination: DestHost may be an IP-literal spelling
			// of DestIP. That is not a malformed hostname; attribution
			// enforces DestIP/DestHost agreement.
			if _, ipErr := netip.ParseAddr(strings.Trim(step.DestHost, "[]")); ipErr != nil {
				return false, fmt.Errorf("%w: malformed structured DestHost %q", ErrInvalidStep, step.DestHost)
			}
		}
		return true, nil
	}
	if step.DestIP.IsValid() {
		return true, nil
	}
	return false, nil
}

// egressFromArgs reports whether the mediated tool call (name or args)
// requests network egress: a network tool (curl/wget/http_get/fetch/request)
// or a URL/IP argument. Deterministic and redacted-args-only.
//
// Rev 11 (reviewer run 191): matching is EXACT-or-http-PREFIX on the
// documented network tool names and BOUNDARY-AWARE on arguments. Substring
// matching is a false-positive source: "request_review", "networking",
// "fetch_data", "curly", "wgetters" are not egress requests.
//
// Rev 15 (reviewer run 200): args extraction is COMMAND-BEARING-KEY-AWARE —
// a URL/network-tool token in an arg value counts ONLY under a
// command-bearing key (`command`/`cmd`/`args`/`arguments`/`executable`/
// `shell_command`). `write_file` `content:"curl"` is benign payload, not a
// mediated egress request.
//
// Codex P1: a STRUCTURED DestHost/DestIP is authoritative proof of an
// egress request, orthogonal to the args scan. Malformed DestHost still
// reports true here so ExtractSignals emits the boundary signal; Eval
// fails closed via EffectAttributable's evaluator-error path.
func egressFromArgs(step Step, blob string) bool {
	if ok, err := structuredDestination(step); err != nil || ok {
		return true
	}
	t := strings.ToLower(step.Tool)
	if isNetToolName(t) {
		return true
	}
	if argsContainURLOrNetTool(step.Args) {
		return true
	}
	_ = blob
	return false
}

// isNetToolName reports whether the tool name is a documented network-tool
// surface: an EXACT match on curl/wget/http_get/http/fetch/request/net/
// web_fetch/browse/fetch_url, or any tool starting with "http"
// (http_get, http-client, http_request).
func isNetToolName(t string) bool {
	t = canonicalCommandToken(t)
	switch t {
	case "curl", "wget", "http_get", "http", "fetch", "request", "net",
		"web_fetch", "browse", "fetch_url":
		return true
	}
	return strings.HasPrefix(t, "http")
}

// argsContainURLOrNetTool reports whether any arg value under a
// COMMAND-BEARING KEY contains an http(s) URL or an exact network-tool token
// (curl/wget) at a command boundary. Rev 15 (reviewer run 200): non-command
// keys (`content`, `url` as pure data, `output`, `body`) are never scanned —
// `write_file` `content:"curl"` is benign payload, not an egress request.
func argsContainURLOrNetTool(args map[string]string) bool {
	for _, v := range commandBearingArgs(args) {
		lv := strings.ToLower(v)
		for _, tok := range shellTokens(lv) {
			if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
				return true
			}
			switch canonicalCommandToken(tok) {
			case "curl", "wget":
				return true
			}
		}
	}
	return false
}

// hasSignal reports whether a signal of the given kind is already present.
func hasSignal(signals []Signal, kind string) bool {
	for _, s := range signals {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

// confirmedDelta is D1/D4: a confirmed lattice primitive requires a
// non-declared signal at matching evidence. Declared intent and artifact
// construction never confirm. Runtime markers confirm bug A/B only on a
// pure in-envelope observation step. Boundary requests confirm the
// requested out-of-envelope primitive (recorded, not executed).
//
// Rev 10 (reviewer run 189): the effect kind used for the switch is the
// DERIVED kind (the same value Eval bound for attribution), so an
// args/tool-derived boundary signal with an empty structured Effect still
// records its capability delta.
func confirmedDelta(step Step, signals []Signal, attrib bool, held []string) []string {
	var add []string
	effect := step.Effect
	if effect == "" {
		effect = deriveEffectKind(step, signals)
	}
	switch effect {
	case EffectHostExec:
		if hasSignalLevel(signals, SignalBoundaryHostExec, EvidenceBoundaryRequest) {
			add = []string{CapHostExec}
		}
	case EffectNetEgress:
		if hasSignalLevel(signals, SignalBoundaryEgress, EvidenceBoundaryRequest) {
			add = []string{CapNetEgress}
		}
	case "":
		// Pure observation step (mediated result scan). Only in-envelope
		// (attributable) runtime markers confirm deltas.
		if !attrib {
			break
		}
		if hasSignalLevel(signals, SignalRuntimeMemoryCorruption, EvidenceRuntimeMarker) {
			add = []string{CapOOBRead, CapOOBWrite}
		} else if hasSignalLevel(signals, SignalRuntimeSandboxEscape, EvidenceRuntimeMarker) {
			add = []string{CapHeapEscape, CapNativeExec}
		}
	}
	return newlyHeld(add, held)
}

// bindDerivedTarget canonicalizes a derived boundary step (Rev 10, reviewer
// run 189): when the structured Effect was empty but ExtractSignals derived
// a boundary kind from the tool/args surface, populate the canonical
// observation fields so EffectAttributable can make a deterministic
// decision.
//
// host_exec: the observed executable is derived ONLY from the mediated tool
// name when the tool name itself IS a host-exec surface (bash/sh/
// /bin/sh//bin/bash/host_exec/shell) — the tool name is then the executable.
// An args-only surface (e.g. Tool:"exec", Args:{"command":"/bin/bash -c id"})
// has NO attributable structured executable: bindDerivedTarget leaves
// Executable empty and EffectAttributable fails closed (missing target →
// evaluator error → PAUSE). We never invent an executable from the generic
// tool name ("exec" is not "bash") — that would be false attribution.
//
// net_egress: the raw EffectTarget is set from DestIP/DestHost when those
// are populated; an args-derived URL (e.g. "curl http://evil.example/x")
// becomes the raw target. A surface with NO target anywhere fails closed in
// EffectAttributable (missing raw target → evaluator error → PAUSE).
func bindDerivedTarget(step Step, kind string) Step {
	switch kind {
	case EffectHostExec:
		// Rev 11 (reviewer run 191): the derived host_exec executable comes
		// ONLY from the canonical host-exec TOOL NAME. Caller-supplied
		// structured Executable/EffectTarget fields are NOT trusted when the
		// structured Effect was empty and the tool name is NOT itself a
		// host-exec surface: a generic tool (e.g. "exec") whose ARGS carry a
		// shell surface has no attributable executable, and using the
		// caller's pre-populated Executable would let an args-only surface
		// reach ALLOW. We fail closed in EffectAttributable (missing target
		// → evaluator error → PAUSE).
		exe := ""
		if isHostExecToolName(strings.ToLower(step.Tool)) {
			exe = canonicalCommandToken(strings.ToLower(step.Tool))
		}
		step.Effect = EffectHostExec
		step.Executable = exe
		step.EffectTarget = exe
	case EffectNetEgress:
		step.Effect = EffectNetEgress
		if step.EffectTarget == "" {
			if step.DestIP.IsValid() {
				step.EffectTarget = step.DestIP.String()
			} else if step.DestHost != "" {
				step.EffectTarget = step.DestHost
			} else if u := egressURLFromArgs(step); u != "" {
				step.EffectTarget = u
			}
		}
		// Rev 14 (Mayur operator decision, run 197): the derived
		// EffectFileAccess case is REMOVED — deriveEffectKind no longer derives
		// file_access from SignalBoundaryFileOutside. A file-outside observation
		// without an explicit Effect is untyped and fails closed in Eval. There
		// is no derived file target to bind.
	}
	return step
}

// egressURLFromArgs returns the first http(s) DESTINATION found in the args
// surface (deterministic sorted-key scan), or "". The destination is the
// URL's host (with port stripped), which is what EffectAttributable
// validates as the net_egress target — a bare URL is not a canonical
// hostname target. An IP-literal host (http://10.0.0.7/x) is returned as
// the IP literal so attribution's IP branch handles it.
func egressURLFromArgs(step Step) string {
	for _, k := range sortedKeys(step.Args) {
		for _, tok := range strings.Fields(step.Args[k]) {
			lt := strings.ToLower(tok)
			if !strings.HasPrefix(lt, "http://") && !strings.HasPrefix(lt, "https://") {
				continue
			}
			rest := tok
			if i := strings.Index(rest, "://"); i >= 0 {
				rest = rest[i+3:]
			}
			if i := strings.IndexAny(rest, "/?#"); i >= 0 {
				rest = rest[:i]
			}
			if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[:i], ":") {
				// host:port (single colon = port; IPv6 literal keeps colons)
				rest = rest[:i]
			}
			rest = strings.TrimPrefix(rest, "[")
			rest = strings.TrimSuffix(rest, "]")
			if rest == "" {
				continue
			}
			return rest
		}
	}
	return ""
}

// sortedKeys returns the sorted keys of a map (deterministic scan order).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// deriveEffectKind binds an args/tool-derived boundary signal (Rev 10,
// reviewer run 189) to a canonical effect kind when the structured
// Step.Effect is empty. Returns "" when no boundary signal is present
// (a pure observation step stays non-boundary). When a boundary signal IS
// present but the observed surface provides no target, the kind is still
// returned — EffectAttributable then fails closed on the missing target
// (evaluator error → PAUSE), never ALLOW.
func deriveEffectKind(step Step, signals []Signal) string {
	if hasSignalLevel(signals, SignalBoundaryHostExec, EvidenceBoundaryRequest) {
		return EffectHostExec
	}
	if hasSignalLevel(signals, SignalBoundaryEgress, EvidenceBoundaryRequest) {
		return EffectNetEgress
	}
	// Rev 14 (Mayur operator decision, run 197): SignalBoundaryFileOutside
	// has NO derived kind. The empty-Effect file-boundary derivation is
	// removed entirely — a file-outside observation without an explicit
	// structured Effect is UNTYPED and fails closed (evaluator error →
	// PAUSE) via Eval's untyped guard. File_access is only ever the
	// EXPLICIT structured Effect (case EffectFileAccess in ExtractSignals
	// and EffectAttributable).
	return ""
}

// requestedEffectCapability names the capability requested by a boundary
// effect when the delta itself carried none (mirrors CDR detector.go).
func requestedEffectCapability(step Step) string {
	switch step.Effect {
	case EffectHostExec:
		return CapHostExec
	case EffectNetEgress:
		return CapNetEgress
	case EffectCanaryAccess:
		return EffectCanaryAccess
	}
	return step.Effect
}

func hasSignalLevel(signals []Signal, kind, level string) bool {
	for _, s := range signals {
		if s.Kind == kind && s.EvidenceLevel == level {
			return true
		}
	}
	return false
}

// hasBoundarySignal reports whether the signal set carries ANY
// boundary_request-level signal (kind 6-8). Rev 14: used by Eval's untyped
// fail-closed guard — a boundary observation with empty Effect and no
// attributable derived kind must fail closed, never ALLOW.
func hasBoundarySignal(signals []Signal) bool {
	for _, s := range signals {
		switch s.Kind {
		case SignalBoundaryHostExec, SignalBoundaryEgress, SignalBoundaryFileOutside:
			return true
		}
	}
	return false
}

func cloneCaps(in []string) []string {
	out := make([]string, 0, len(in))
	return append(out, in...)
}

// cloneSignals returns a defensive copy of the signal slice. The sealed
// receipt must never alias caller-owned memory (reviewer run 183): Eval
// copies before receipt construction so a later mutation of the caller's
// Step.Signals cannot change the receipt contents or invalidate its hash.
func cloneSignals(in []Signal) []Signal {
	out := make([]Signal, len(in))
	copy(out, in)
	return out
}

func newlyHeld(add, held []string) []string {
	have := capSet(held)
	out := make([]string, 0, len(add))
	for _, c := range add {
		if have[c] {
			continue
		}
		out = append(out, c)
	}
	return out
}

func unionLattice(before, delta []string) []string {
	have := capSet(before)
	for _, c := range delta {
		have[c] = true
	}
	out := make([]string, 0, len(have))
	for _, c := range lattice {
		if have[c] {
			out = append(out, c)
		}
	}
	return out
}

func highestCapability(caps []string) string {
	rank := make(map[string]int, len(lattice))
	for i, c := range lattice {
		rank[c] = i
	}
	best := ""
	bestRank := -1
	for _, c := range caps {
		if r, ok := rank[c]; ok && r > bestRank {
			bestRank = r
			best = c
		}
	}
	return best
}

func capSet(caps []string) map[string]bool {
	out := make(map[string]bool, len(caps))
	for _, c := range caps {
		out[c] = true
	}
	return out
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var memoryCorruptionMarkers = []string{
	"SIGSEGV", "SIGABRT", "AddressSanitizer", "heap-buffer-overflow",
	"SEGV_MAPERR", "stack-buffer-overflow",
}

var sandboxEscapeMarkers = []string{
	"sandbox escape", "container escape", "namespace", "landlock", "seccomp",
}

// isBuildTool reports whether the TOOL NAME is a build/exec surface. Rev 11
// (reviewer run 191): TOKEN-BOUNDARY-AWARE — a bare substring match makes
// "access" (contains "cc") or "clangorous" a build tool. Exact compiler
// names (optionally with `-flags`) and the exact "go build" phrase count.
func isBuildTool(tool string) bool {
	t := strings.ToLower(tool)
	if t == "go build" {
		return true
	}
	switch compilerTokenBase(t) {
	case "gcc", "clang", "cc":
		return true
	}
	return false
}

// matchMarkers returns every marker in haystack (in marker-list order).
func matchMarkers(haystack string, markers []string) []string {
	var out []string
	for _, m := range markers {
		if strings.Contains(haystack, m) {
			out = append(out, m)
		}
	}
	return out
}
