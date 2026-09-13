package incidentbench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
)

type KindCount struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type Latency struct {
	Unit  string `json:"unit"`
	Count int    `json:"count"`
	Min   int64  `json:"min"`
	P50   int64  `json:"p50"`
	P95   int64  `json:"p95"`
	Max   int64  `json:"max"`
}

type Report struct {
	SchemaVersion           int         `json:"schema_version"`
	Coverage                string      `json:"coverage"`
	CorpusSeed              uint32      `json:"corpus_seed"`
	TrajectoryCount         int         `json:"trajectory_count"`
	DeliveryCount           int         `json:"delivery_count"`
	EffectKindCounts        []KindCount `json:"effect_kind_counts"`
	ExpectedIncidentCount   int         `json:"expected_incident_count"`
	EmittedIncidentCount    int         `json:"emitted_incident_count"`
	TruePositiveCount       int         `json:"true_positive_count"`
	FalseNegativeCount      int         `json:"false_negative_count"`
	FalsePositiveCount      int         `json:"false_positive_count"`
	DuplicatePersistCount   int         `json:"duplicate_persist_count"`
	CompleteReceiptCount    int         `json:"complete_receipt_count"`
	Recall                  float64     `json:"recall"`
	Precision               float64     `json:"precision"`
	FalsePositiveRate       float64     `json:"false_positive_rate"`
	DuplicateRate           float64     `json:"duplicate_rate"`
	ReceiptCompleteness     float64     `json:"receipt_completeness"`
	EffectToIncidentLatency Latency     `json:"effect_to_incident_latency"`
	CorpusDigest            string      `json:"corpus_digest"`
	ReportDigest            string      `json:"report_digest"`
	Limitations             []string    `json:"limitations"`
}

var defaultLimitations = []string{
	"synthetic local corpus; not a production measurement",
	"MCP action-boundary model only; executor and network boundaries excluded",
	"no live targets, external network, or real credentials",
	"does not prove whole-runtime completeness or bypass resistance",
	"does not establish Wiz remediation or Wiz-fixed status",
}

func Run() (*Report, error) { return RunSize(DefaultCorpusSize) }

func RunSize(n int) (*Report, error) {
	if n < DefaultCorpusSize {
		return nil, fmt.Errorf("corpus size %d below %d", n, DefaultCorpusSize)
	}
	return execute(generate(n))
}

func execute(trajs []Trajectory) (*Report, error) {
	b := NewBoundary()
	rec := NewRecorder()
	deliveries := 0
	kinds := make([]int, len(effectKinds))
	for _, tr := range trajs {
		if err := validateTrajectory(tr); err != nil {
			return nil, err
		}
		for i, k := range effectKinds {
			if tr.RequestedEffect.Kind == k {
				kinds[i]++
				break
			}
		}
		b.setReachable(tr.RequestedEffect.Target, hasFixture(tr.DeclaredEnvironment.FixtureIDs, tr.RequestedEffect.Target))
		for _, d := range tr.Deliveries {
			deliveries++
			res, err := b.Evaluate(tr, d)
			if err != nil {
				return nil, err
			}
			if _, err := rec.Record(tr, res); err != nil {
				return nil, err
			}
		}
	}
	return assemble(trajs, rec, deliveries, kinds), nil
}

func nearestRank(sorted []int64, p float64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

func latencyStats(vals []int64) Latency {
	out := Latency{Unit: "logical_tick", Count: len(vals)}
	if len(vals) == 0 {
		return out
	}
	s := slices.Clone(vals)
	slices.Sort(s)
	out.Min, out.Max = s[0], s[len(s)-1]
	out.P50, out.P95 = nearestRank(s, 50), nearestRank(s, 95)
	return out
}

func fillRates(r *Report) {
	tp, fn, fp := r.TruePositiveCount, r.FalseNegativeCount, r.FalsePositiveCount
	if tp+fn > 0 {
		r.Recall = float64(tp) / float64(tp+fn)
	}
	if tp+fp > 0 {
		r.Precision = float64(tp) / float64(tp+fp)
	}
	if non := r.TrajectoryCount - r.ExpectedIncidentCount; non > 0 {
		r.FalsePositiveRate = float64(fp) / float64(non)
	}
	if r.ExpectedIncidentCount > 0 {
		r.DuplicateRate = float64(r.DuplicatePersistCount) / float64(r.ExpectedIncidentCount)
	}
	if r.EmittedIncidentCount > 0 {
		r.ReceiptCompleteness = float64(r.CompleteReceiptCount) / float64(r.EmittedIncidentCount)
	}
}

func assemble(trajs []Trajectory, rec *Recorder, deliveries int, kinds []int) *Report {
	var tp, fn, fp int
	var lats []int64
	for _, tr := range trajs {
		key := DedupKey(tr)
		got, ok := rec.byKey[key]
		exp := tr.scenario >= 1 && tr.scenario <= 5
		switch {
		case exp && ok:
			tp++
			lats = append(lats, int64(got.PersistedTick-got.BoundaryTick))
		case exp && !ok:
			fn++
		case !exp && ok:
			fp++
		}
	}
	kc := make([]KindCount, len(effectKinds))
	for i, k := range effectKinds {
		kc[i] = KindCount{Kind: k, Count: kinds[i]}
	}
	r := &Report{
		SchemaVersion: SchemaVersion, Coverage: Coverage, CorpusSeed: CorpusSeed,
		TrajectoryCount: len(trajs), DeliveryCount: deliveries, EffectKindCounts: kc,
		ExpectedIncidentCount: tp + fn, EmittedIncidentCount: len(rec.byKey),
		TruePositiveCount: tp, FalseNegativeCount: fn, FalsePositiveCount: fp,
		DuplicatePersistCount: 0, CompleteReceiptCount: len(rec.byKey),
		EffectToIncidentLatency: latencyStats(lats), CorpusDigest: corpusDigest(trajs),
		Limitations: slices.Clone(defaultLimitations),
	}
	fillRates(r)
	raw, _ := json.Marshal(r)
	sum := sha256.Sum256(raw)
	r.ReportDigest = hex.EncodeToString(sum[:])
	return r
}
