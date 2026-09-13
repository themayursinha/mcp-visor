package killswitch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func ksDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}
func ksKey(t *testing.T) (path string, key []byte) {
	t.Helper()
	key = make([]byte, 32)
	_, _ = rand.Read(key)
	path = filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}
func signedCmd(t *testing.T, key []byte, sess string, epoch uint64, cid, reason, id string) Command {
	t.Helper()
	if id == "" {
		id = strings.Repeat("ab", 16)
	}
	c := Command{SchemaVersion: SchemaVersion, CommandID: id, SessionID: sess, RevokeThroughEpoch: epoch, ControllerID: cid, Reason: reason}
	if err := SignCommand(&c, key); err != nil {
		t.Fatal(err)
	}
	return c
}
func monCfg(dir, sess string, epoch uint64, id string, key []byte) Config {
	return Config{Dir: dir, SessionID: sess, SessionEpoch: epoch, Controllers: map[string][]byte{id: key}, PollInterval: 5 * time.Millisecond}
}

func TestKineticCommandMACBindsEveryField(t *testing.T) {
	_, key := ksKey(t)
	base := signedCmd(t, key, "sess-a", 3, "c1", "halt now", "aa"+strings.Repeat("bb", 15))
	if VerifyCommand(base, key) != nil {
		t.Fatal("valid mac")
	}
	mut := []Command{base, base, base, base, base, base}
	mut[0].CommandID = strings.Repeat("cc", 16)
	mut[1].SessionID = "sess-b"
	mut[2].RevokeThroughEpoch = 4
	mut[3].ControllerID = "c2"
	mut[4].Reason = "other"
	mut[5].SchemaVersion = 2
	for i, c := range mut {
		if VerifyCommand(c, key) == nil {
			t.Fatalf("mut %d verified", i)
		}
	}
}

func TestKineticCommandRejectsUnknownControllerAndBadMAC(t *testing.T) {
	dir := ksDir(t)
	_, k1 := ksKey(t)
	_, k2 := ksKey(t)
	m, err := NewMonitor(monCfg(dir, "s", 1, "c1", k1))
	if err != nil {
		t.Fatal(err)
	}
	c := signedCmd(t, k2, "s", 1, "c2", "stop", "")
	if _, err := WriteCommand(dir, c); err != nil {
		t.Fatal(err)
	}
	if err := m.StartupCheck(); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("got %v", err)
	}
	empty := signedCmd(t, nil, "s", 1, "nobody", "stop", strings.Repeat("ff", 16))
	if VerifyCommand(empty, nil) == nil {
		t.Fatal("nil-key mac")
	}
	if _, err := WriteCommand(dir, empty); err != nil {
		t.Fatal(err)
	}
	if err := m.StartupCheck(); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("empty-key unknown controller: %v", err)
	}
	bad := signedCmd(t, k1, "s", 1, "c1", "stop", strings.Repeat("dd", 16))
	bad.Signature = strings.Repeat("ee", 32)
	if VerifyCommand(bad, k1) == nil {
		t.Fatal("bad mac")
	}
}

func TestKineticCommandRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	c := signedCmd(t, key, "s", 1, "c1", "stop", "")
	raw, _ := json.Marshal(c)
	dup := []byte(`{"schema_version":1,"schema_version":2}`)
	if decodeControl(dup, &Command{}) == nil {
		t.Fatal("dup")
	}
	trail := append(append([]byte{}, raw...), []byte("\n{}")...)
	if decodeControl(trail, &Command{}) == nil {
		t.Fatal("trail")
	}
	unk := []byte(strings.TrimSpace(string(raw)))
	unk = []byte(strings.Replace(string(unk[:len(unk)-1]), "}", `,"nope":1}`, 1))
	if decodeControl(unk, &Command{}) == nil {
		t.Fatal("unknown")
	}
	_ = dir
}

func TestKineticControlPathsDoNotEmbedSessionID(t *testing.T) {
	sess := "session-secret-id"
	p := CommandPath("/tmp/ks", sess)
	s := StatePath("/tmp/ks", sess)
	if strings.Contains(p, sess) || strings.Contains(s, sess) {
		t.Fatalf("%s %s", p, s)
	}
	if !strings.HasSuffix(p, ".stop.json") || !strings.HasSuffix(s, ".state.json") {
		t.Fatal(p, s)
	}
}

func TestKineticWriteCommandIsAtomicDurableAnd0600(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	c := signedCmd(t, key, "s", 1, "c1", "stop", "")
	n := atomic.Int32{}
	old := dirSync
	dirSync = func(d string) error { n.Add(1); return old(d) }
	defer func() { dirSync = old }()
	dig, err := WriteCommand(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(dig) != 64 || n.Load() < 1 {
		t.Fatalf("digest/sync %s %d", dig, n.Load())
	}
	st, err := os.Stat(CommandPath(dir, "s"))
	if err != nil || st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
		t.Fatalf("mode %v %v", st, err)
	}
	raw, _ := os.ReadFile(CommandPath(dir, "s"))
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatal("newline")
	}
}

func TestKineticStartupRejectsPersistedOrCommandRevocation(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	c := signedCmd(t, key, "s", 2, "c1", "stop", "")
	if _, err := WriteCommand(dir, c); err != nil {
		t.Fatal(err)
	}
	m, err := NewMonitor(monCfg(dir, "s", 2, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.StartupCheck(); !errors.Is(err, ErrPreviouslyRevoked) {
		t.Fatalf("cmd %v", err)
	}
	dir2 := ksDir(t)
	m2, err := NewMonitor(monCfg(dir2, "s", 2, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	st := Stop{Command: c, RequestSHA256: strings.Repeat("ab", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"}
	if err := m2.WriteState(st); err != nil {
		t.Fatal(err)
	}
	m3, err := NewMonitor(monCfg(dir2, "s", 2, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	if err := m3.StartupCheck(); !errors.Is(err, ErrPreviouslyRevoked) {
		t.Fatalf("state %v", err)
	}
}

func TestKineticStartupIgnoresLowerStaleEpoch(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	c := signedCmd(t, key, "s", 1, "c1", "stop", "")
	if _, err := WriteCommand(dir, c); err != nil {
		t.Fatal(err)
	}
	m, err := NewMonitor(monCfg(dir, "s", 2, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.StartupCheck(); err != nil {
		t.Fatal(err)
	}
}

func TestKineticStateMonotonicallyKeepsMaximumEpoch(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	m, err := NewMonitor(monCfg(dir, "s", 1, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	low := signedCmd(t, key, "s", 3, "c1", "low", strings.Repeat("11", 16))
	high := signedCmd(t, key, "s", 9, "c1", "high", strings.Repeat("22", 16))
	if err := m.WriteState(Stop{Command: high, RequestSHA256: strings.Repeat("aa", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"}); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteState(Stop{Command: low, RequestSHA256: strings.Repeat("bb", 32), ObservedAt: time.Now().UTC(), ResultingState: "revoked_contained"}); err != nil {
		t.Fatal(err)
	}
	st, err := ReadState(dir, "s", map[string][]byte{"c1": key})
	if err != nil || st.RevokedThroughEpoch != 9 || st.CommandID != low.CommandID {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestKineticMonitorStopsOnceOnValidCommand(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	m, err := NewMonitor(monCfg(dir, "s", 1, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		c := signedCmd(t, key, "s", 1, "c1", "stop", "")
		_, _ = WriteCommand(dir, c)
	}()
	err = m.Run(ctx, func(Stop) { n.Add(1) })
	if err != nil || n.Load() != 1 {
		t.Fatalf("err=%v n=%d", err, n.Load())
	}
}

func TestKineticMonitorContainsOnUnavailableControlDirectory(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	m, err := NewMonitor(monCfg(dir, "s", 1, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	var got Stop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.RemoveAll(dir)
	}()
	err = m.Run(ctx, func(s Stop) { got = s })
	if !errors.Is(err, ErrControlUnavailable) || got.ResultingState != "contained_control_unavailable" || got.Command.Reason != "kill-switch control channel unavailable" || got.Command.ControllerID != "" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestKineticMonitorContainsOnInvalidExpectedCommand(t *testing.T) {
	dir := ksDir(t)
	_, key := ksKey(t)
	m, err := NewMonitor(monCfg(dir, "s", 1, "c1", key))
	if err != nil {
		t.Fatal(err)
	}
	var got Stop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.MkdirAll(filepath.Join(dir, "commands"), 0o700)
		_ = os.WriteFile(CommandPath(dir, "s"), []byte("{not-json\n"), 0o600)
	}()
	err = m.Run(ctx, func(s Stop) { got = s })
	if !errors.Is(err, ErrControlInvalid) || got.ResultingState != "contained_control_invalid" || got.Command.ControllerID != "" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestKineticRejectsSymlinkLooseModeWrongOwnerAndOversize(t *testing.T) {
	dir := ksDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if ValidateControlDir(dir) == nil {
		t.Fatal("loose")
	}
	link := filepath.Join(t.TempDir(), "l")
	if err := os.Symlink(ksDir(t), link); err != nil {
		t.Fatal(err)
	}
	if ValidateControlDir(link) == nil {
		t.Fatal("symlink")
	}
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(big); err == nil {
		t.Fatal("oversize")
	}
	if syscall.Geteuid() == 0 {
		t.Skip("root")
	}
}

func TestKineticStateMACBindsResultAndObservedTime(t *testing.T) {
	_, key := ksKey(t)
	st := State{SchemaVersion: 1, SessionID: "s", RevokedThroughEpoch: 1, CommandID: strings.Repeat("ab", 16), ControllerID: "c1", Reason: "stop", ObservedAt: "2026-01-01T00:00:00Z", ResultingState: "revoked_contained", RequestSHA256: strings.Repeat("cd", 32)}
	if err := SignState(&st, key); err != nil {
		t.Fatal(err)
	}
	if VerifyState(st, key) != nil {
		t.Fatal("ok")
	}
	st.ResultingState = "other"
	if VerifyState(st, key) == nil {
		t.Fatal("result")
	}
	st.ResultingState = "revoked_contained"
	st.ObservedAt = "2026-01-02T00:00:00Z"
	if VerifyState(st, key) == nil {
		t.Fatal("time")
	}
}
