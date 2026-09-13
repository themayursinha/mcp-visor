package trajectory

import "sync"

const (
	windowTransitions = 32
	warmupTransitions = 8
	minSourceSupport  = 2
	advisorName       = "session_unseen_bigram_v1"
	anomalyKind       = "unseen_successor"
)

type Observation struct {
	Server string
	Tool   string
}

type Advice struct {
	Advisor           string
	Kind              string
	Sequence          []string
	WindowTransitions int
	SourceSupport     uint64
	TransitionSupport uint64
}

type token struct {
	server, tool string
}

type directed struct {
	from, to token
}

type Advisor struct {
	mu      sync.Mutex
	tokens  []token
	sources map[token]uint64
	bigrams map[directed]uint64
}

func New() *Advisor {
	return &Advisor{
		tokens:  make([]token, 0, windowTransitions+1),
		sources: make(map[token]uint64),
		bigrams: make(map[directed]uint64),
	}
}

func render(tok token) string { return tok.server + ":" + tok.tool }

func (a *Advisor) Assess(observation Observation) (Advice, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cand := token{server: observation.Server, tool: observation.Tool}
	if len(a.tokens) == 0 {
		a.tokens = append(a.tokens, cand)
		return Advice{}, false
	}
	prev := a.tokens[len(a.tokens)-1]
	windowCount := len(a.tokens) - 1
	sourceSupport := a.sources[prev]
	transitionSupport := a.bigrams[directed{from: prev, to: cand}]
	flagged := windowCount >= warmupTransitions && sourceSupport >= minSourceSupport && transitionSupport == 0
	var advice Advice
	if flagged {
		advice = Advice{
			Advisor:           advisorName,
			Kind:              anomalyKind,
			Sequence:          []string{render(prev), render(cand)},
			WindowTransitions: windowCount,
			SourceSupport:     sourceSupport,
			TransitionSupport: 0,
		}
	}
	a.bigrams[directed{from: prev, to: cand}]++
	a.sources[prev]++
	a.tokens = append(a.tokens, cand)
	if len(a.tokens)-1 > windowTransitions {
		from, to := a.tokens[0], a.tokens[1]
		key := directed{from: from, to: to}
		a.bigrams[key]--
		if a.bigrams[key] == 0 {
			delete(a.bigrams, key)
		}
		a.sources[from]--
		if a.sources[from] == 0 {
			delete(a.sources, from)
		}
		copy(a.tokens, a.tokens[1:])
		a.tokens = a.tokens[:len(a.tokens)-1]
	}
	if flagged {
		return advice, true
	}
	return Advice{}, false
}
