package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

type ArgValidator struct {
	compiledDenyPatterns  []*compiledPattern
	compiledAllowPatterns []*compiledPattern
	compiledDenyRegex     []*regexp.Regexp
	compiledAllowRegex    []*regexp.Regexp
}

type compiledPattern struct {
	original string
	regex    *regexp.Regexp
}

func NewArgValidator() *ArgValidator {
	return &ArgValidator{}
}

func (v *ArgValidator) Compile(rules []ArgRule) {
	for _, rule := range rules {
		for _, pattern := range rule.Patterns {
			compiled := v.compileGlob(pattern)
			switch rule.Type {
			case "deny_path", "deny_command_pattern", "deny_query_pattern":
				v.compiledDenyPatterns = append(v.compiledDenyPatterns, compiled)
			case "allow_path", "allow_command_pattern", "allow_query_pattern":
				v.compiledAllowPatterns = append(v.compiledAllowPatterns, compiled)
			}
		}
	}
}

func (v *ArgValidator) compileGlob(pattern string) *compiledPattern {
	regexStr := globToRegex(pattern)
	re, err := regexp.Compile(regexStr)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(pattern))
	}
	return &compiledPattern{original: pattern, regex: re}
}

func globToRegex(pattern string) string {
	s := regexp.QuoteMeta(pattern)
	s = strings.ReplaceAll(s, `\*\*`, `.*`)
	s = strings.ReplaceAll(s, `\*`, `[^/]*`)
	return "(?i)^" + s + "$"
}

func (v *ArgValidator) MatchPath(path string) (denied bool, reason string) {
	for _, p := range v.compiledDenyPatterns {
		if p.regex.MatchString(path) || v.matchGlobPath(p.original, path) {
			return true, "path matches deny pattern: " + p.original
		}
	}
	if len(v.compiledAllowPatterns) > 0 {
		allowed := false
		for _, p := range v.compiledAllowPatterns {
			if p.regex.MatchString(path) || v.matchGlobPath(p.original, path) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, "path does not match any allow pattern"
		}
	}
	return false, ""
}

func (v *ArgValidator) matchGlobPath(pattern, path string) bool {
	match, _ := filepath.Match(pattern, path)
	if match {
		return true
	}
	match, _ = filepath.Match(strings.ToLower(pattern), strings.ToLower(path))
	return match
}

func (v *ArgValidator) MatchCommand(cmd string) (denied bool, reason string) {
	for _, p := range v.compiledDenyPatterns {
		if p.regex.MatchString(cmd) {
			return true, "command matches deny pattern: " + p.original
		}
	}
	if len(v.compiledAllowPatterns) > 0 {
		allowed := false
		for _, p := range v.compiledAllowPatterns {
			if p.regex.MatchString(cmd) {
				allowed = true
				break
			}
		}
		if !allowed {
			return true, "command does not match any allow pattern"
		}
	}
	return false, ""
}

func MatchesGlob(pattern, s string) bool {
	match, err := filepath.Match(pattern, s)
	if err != nil {
		return false
	}
	return match
}

func MatchesAnyDomain(allowedDomains []string, url string) bool {
	for _, domain := range allowedDomains {
		if MatchesGlob(domain, url) {
			return true
		}
	}
	return false
}

func MatchesAnyRepo(allowedRepos []string, repo string) bool {
	for _, r := range allowedRepos {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}

func MatchesAnyDomainPattern(domains []string, url string) (bool, string) {
	for _, domain := range domains {
		if strings.Contains(url, domain) {
			return true, domain
		}
	}
	return false, ""
}
