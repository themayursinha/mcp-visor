package trajectory

import (
	"sync"
	"testing"
)

func ob(server, tool string) Observation {
	return Observation{Server: server, Tool: tool}
}

func quiet(t *testing.T, a *Advisor, o Observation) {
	t.Helper()
	if adv, ok := a.Assess(o); ok {
		t.Fatalf("unexpected flag %+v for %+v", adv, o)
	}
}

func flag(t *testing.T, a *Advisor, o Observation) Advice {
	t.Helper()
	adv, ok := a.Assess(o)
	if !ok {
		t.Fatalf("want flag for %+v", o)
	}
	if adv.Advisor != "session_unseen_bigram_v1" || adv.Kind != "unseen_successor" {
		t.Fatalf("advisor/kind: %+v", adv)
	}
	if adv.TransitionSupport != 0 || len(adv.Sequence) != 2 {
		t.Fatalf("sequence/support: %+v", adv)
	}
	return adv
}

func feed(t *testing.T, a *Advisor, steps []Observation) {
	t.Helper()
	for _, o := range steps {
		quiet(t, a, o)
	}
}

func TestAssessNeverFlagsBeforeWarmup(t *testing.T) {
	a := New()
	quiet(t, a, ob("s", "a"))
	for _, o := range []Observation{
		ob("s", "b"), ob("s", "a"), ob("s", "b"), ob("s", "a"),
		ob("s", "b"), ob("s", "a"), ob("s", "b"), ob("s", "a"),
	} {
		quiet(t, a, o)
	}
}

func TestAssessFlagsAtEightTransitionsAndSourceSupportTwo(t *testing.T) {
	a := New()
	feed(t, a, []Observation{
		ob("s", "a"), ob("s", "b"), ob("s", "a"), ob("s", "b"),
		ob("s", "x"), ob("s", "y"), ob("s", "x"), ob("s", "y"), ob("s", "x"),
	})
	adv := flag(t, a, ob("s", "z"))
	if adv.WindowTransitions != 8 || adv.SourceSupport != 2 {
		t.Fatalf("warmup boundary: %+v", adv)
	}
	if adv.Sequence[0] != "s:x" || adv.Sequence[1] != "s:z" {
		t.Fatalf("sequence: %v", adv.Sequence)
	}
}

func TestAssessSourceSupportOneDoesNotFlag(t *testing.T) {
	a := New()
	feed(t, a, []Observation{
		ob("s", "b"), ob("s", "c"), ob("s", "b"), ob("s", "c"),
		ob("s", "b"), ob("s", "c"), ob("s", "b"), ob("s", "c"),
		ob("s", "x"), ob("s", "y"), ob("s", "x"),
	})
	quiet(t, a, ob("s", "z"))
}

func TestAssessSeenSuccessorDoesNotFlag(t *testing.T) {
	a := New()
	feed(t, a, []Observation{
		ob("s", "a"), ob("s", "b"), ob("s", "a"), ob("s", "b"),
		ob("s", "x"), ob("s", "y"), ob("s", "x"), ob("s", "y"), ob("s", "x"),
	})
	quiet(t, a, ob("s", "y"))
}

func TestAssessServerIdentityIsDistinctSuccessor(t *testing.T) {
	a := New()
	feed(t, a, []Observation{
		ob("s", "a"), ob("s", "b"), ob("s", "a"), ob("s", "b"),
		ob("s", "x"), ob("s", "y"), ob("s", "x"), ob("s", "y"), ob("s", "x"),
	})
	adv := flag(t, a, ob("other", "y"))
	if adv.Sequence[0] != "s:x" || adv.Sequence[1] != "other:y" {
		t.Fatalf("sequence: %v", adv.Sequence)
	}
}

func TestAssessAdviceFields(t *testing.T) {
	a := New()
	feed(t, a, []Observation{
		ob("fs", "a"), ob("fs", "b"), ob("fs", "a"), ob("fs", "b"),
		ob("fs", "read"), ob("fs", "write"), ob("fs", "read"), ob("fs", "write"), ob("fs", "read"),
	})
	adv := flag(t, a, ob("fs", "delete"))
	if adv.Advisor != "session_unseen_bigram_v1" || adv.Kind != "unseen_successor" {
		t.Fatalf("fields: %+v", adv)
	}
	if adv.WindowTransitions != 8 || adv.SourceSupport != 2 || adv.TransitionSupport != 0 {
		t.Fatalf("counts: %+v", adv)
	}
	if len(adv.Sequence) != 2 || adv.Sequence[0] != "fs:read" || adv.Sequence[1] != "fs:delete" {
		t.Fatalf("sequence: %v", adv.Sequence)
	}
}

func TestAssessWindowEviction(t *testing.T) {
	a := New()
	var steps []Observation
	for i := 0; i < 16; i++ {
		steps = append(steps, ob("s", "x"), ob("s", "y"))
	}
	steps = append(steps, ob("s", "x"))
	feed(t, a, steps)
	flag(t, a, ob("s", "z"))
	for i := 0; i < 32; i++ {
		a.Assess(ob("s", "z"))
	}
	a.Assess(ob("s", "x"))
	quiet(t, a, ob("s", "w"))
}

func TestAssessConcurrent(t *testing.T) {
	a := New()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			tools := []string{"a", "b", "c"}
			for i := 0; i < 64; i++ {
				adv, ok := a.Assess(ob("s", tools[i%3]))
				if !ok {
					continue
				}
				if adv.Advisor != "session_unseen_bigram_v1" || adv.Kind != "unseen_successor" {
					t.Errorf("advisor/kind %+v", adv)
				}
				if adv.TransitionSupport != 0 || len(adv.Sequence) != 2 || adv.WindowTransitions < 8 || adv.SourceSupport < 2 {
					t.Errorf("invalid advice %+v", adv)
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestAssessEmptyStrings(t *testing.T) {
	a := New()
	quiet(t, a, Observation{})
	for i := 0; i < 64; i++ {
		a.Assess(Observation{})
		a.Assess(ob("", "t"))
		a.Assess(ob("s", ""))
	}
}
