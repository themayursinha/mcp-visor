package killswitch

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion   = 1
	PollInterval    = 50 * time.Millisecond
	MaxControlBytes = 16 << 10
	MaxReasonBytes  = 512
	commandMACCtx   = "mcp-visor-kinetic-command-v1"
	stateMACCtx     = "mcp-visor-kinetic-state-v1"
)

var (
	ErrPreviouslyRevoked  = errors.New("kinetic stop: session epoch previously revoked")
	ErrControlUnavailable = errors.New("kinetic stop: control channel unavailable")
	ErrControlInvalid     = errors.New("kinetic stop: control channel invalid")
	ErrUnauthorized       = errors.New("kinetic stop: command unauthorized")
	fileSync              = func(f *os.File) error { return f.Sync() }
	dirSync               = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	validID     = func(s string) bool { return s != "" && len(s) <= 256 && !strings.ContainsRune(s, 0) }
	validReason = func(s string) bool {
		return s != "" && len(s) <= MaxReasonBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
	}
	hmacSum    = func(data, key []byte) []byte { mac := hmac.New(sha256.New, key); mac.Write(data); return mac.Sum(nil) }
	isLowerHex = func(s string, n int) bool {
		return len(s) == n && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > 'f' || (r > '9' && r < 'a') }) < 0
	}
)

type ControllerKey struct {
	ID  string
	Key []byte
}
type Command struct {
	SchemaVersion      int    `json:"schema_version"`
	CommandID          string `json:"command_id"`
	SessionID          string `json:"session_id"`
	RevokeThroughEpoch uint64 `json:"revoke_through_epoch"`
	ControllerID       string `json:"controller_id"`
	Reason             string `json:"reason"`
	Signature          string `json:"signature"`
}
type State struct {
	SchemaVersion       int    `json:"schema_version"`
	SessionID           string `json:"session_id"`
	RevokedThroughEpoch uint64 `json:"revoked_through_epoch"`
	CommandID           string `json:"command_id"`
	ControllerID        string `json:"controller_id"`
	Reason              string `json:"reason"`
	ObservedAt          string `json:"observed_at"`
	ResultingState      string `json:"resulting_state"`
	RequestSHA256       string `json:"request_sha256"`
	Signature           string `json:"signature"`
}
type Config struct {
	Dir          string
	SessionID    string
	SessionEpoch uint64
	Controllers  map[string][]byte
	PollInterval time.Duration
	Now          func() time.Time
}
type Stop struct {
	Command        Command
	RequestSHA256  string
	ObservedAt     time.Time
	ResultingState string
}
type Monitor struct {
	dir, sessionID string
	sessionEpoch   uint64
	controllers    map[string][]byte
	poll           time.Duration
	now            func() time.Time
	state          *State
}

func LoadControllerSpec(spec string) (ControllerKey, error) {
	id, path, ok := strings.Cut(spec, "=")
	key, err := LoadKeyFile(path)
	if !ok || !validID(id) || path == "" || err != nil {
		if err == nil {
			err = fmt.Errorf("malformed controller spec")
		}
		return ControllerKey{}, err
	}
	return ControllerKey{ID: id, Key: key}, nil
}
func LoadKeyFile(path string) ([]byte, error) {
	b, err := readOwnedFile(path, 4096, 0o600)
	if err != nil || !isLowerHex(string(b), 64) {
		return nil, fmt.Errorf("invalid controller key file")
	}
	out := make([]byte, 32)
	_, err = hex.Decode(out, b)
	return out, err
}
func ValidateControlDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("invalid control directory")
	}
	return requireOwner(st)
}
func CommandPath(dir, sessionID string) string {
	h := sha256.Sum256([]byte(sessionID))
	return filepath.Join(dir, "commands", hex.EncodeToString(h[:])+".stop.json")
}
func StatePath(dir, sessionID string) string {
	h := sha256.Sum256([]byte(sessionID))
	return filepath.Join(dir, "state", hex.EncodeToString(h[:])+".state.json")
}
func SignCommand(cmd *Command, key []byte) error {
	err := validateCommand(*cmd, false)
	if err == nil {
		cmd.Signature = hex.EncodeToString(hmacSum(macFields(commandMACCtx, strconv.Itoa(cmd.SchemaVersion), cmd.CommandID, cmd.SessionID, strconv.FormatUint(cmd.RevokeThroughEpoch, 10), cmd.ControllerID, cmd.Reason), key))
	}
	return err
}
func VerifyCommand(cmd Command, key []byte) error {
	raw, err := hex.DecodeString(cmd.Signature)
	if len(key) != 32 || validateCommand(cmd, true) != nil || err != nil || !hmac.Equal(raw, hmacSum(macFields(commandMACCtx, strconv.Itoa(cmd.SchemaVersion), cmd.CommandID, cmd.SessionID, strconv.FormatUint(cmd.RevokeThroughEpoch, 10), cmd.ControllerID, cmd.Reason), key)) {
		return ErrUnauthorized
	}
	return nil
}
func SignState(state *State, key []byte) error {
	err := validateState(*state, false)
	if err == nil {
		state.Signature = hex.EncodeToString(hmacSum(macFields(stateMACCtx, strconv.Itoa(state.SchemaVersion), state.SessionID, strconv.FormatUint(state.RevokedThroughEpoch, 10), state.CommandID, state.ControllerID, state.Reason, state.ObservedAt, state.ResultingState, state.RequestSHA256), key))
	}
	return err
}
func VerifyState(state State, key []byte) error {
	raw, err := hex.DecodeString(state.Signature)
	if len(key) != 32 || validateState(state, true) != nil || err != nil || !hmac.Equal(raw, hmacSum(macFields(stateMACCtx, strconv.Itoa(state.SchemaVersion), state.SessionID, strconv.FormatUint(state.RevokedThroughEpoch, 10), state.CommandID, state.ControllerID, state.Reason, state.ObservedAt, state.ResultingState, state.RequestSHA256), key)) {
		return ErrUnauthorized
	}
	return nil
}
func WriteCommand(dir string, cmd Command) (string, error) {
	cdir := filepath.Join(dir, "commands")
	err := validateSubdir(dir, "commands", true)
	data, err2 := json.Marshal(cmd)
	if err != nil || err2 != nil || ValidateControlDir(dir) != nil || validateCommand(cmd, true) != nil {
		return "", fmt.Errorf("invalid kinetic command or directory")
	}
	data = append(data, '\n')
	path := CommandPath(dir, cmd.SessionID)
	err = withPublishLock(cdir, func() error {
		if raw, e := readControlFile(path); e == nil {
			var prev Command
			if decodeControl(raw, &prev) == nil && prev.SessionID == cmd.SessionID && prev.RevokeThroughEpoch > cmd.RevokeThroughEpoch {
				return fmt.Errorf("weaker kinetic command")
			}
		}
		return atomicWrite(cdir, path, data)
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func ReadState(dir, sessionID string, controllers map[string][]byte) (State, error) {
	raw, err := readControlFile(StatePath(dir, sessionID))
	if err != nil {
		return State{}, err
	}
	var st State
	if decodeControl(raw, &st) != nil {
		return State{}, ErrControlInvalid
	}
	key, ok := controllers[st.ControllerID]
	if st.SessionID != sessionID || !ok || VerifyState(st, key) != nil {
		return State{}, ErrControlInvalid
	}
	return st, nil
}
func NewMonitor(cfg Config) (*Monitor, error) {
	if cfg.Dir == "" || !validID(cfg.SessionID) || cfg.SessionEpoch < 1 || len(cfg.Controllers) == 0 || ValidateControlDir(cfg.Dir) != nil || validateSubdir(cfg.Dir, "commands", true) != nil || validateSubdir(cfg.Dir, "state", true) != nil {
		return nil, fmt.Errorf("invalid kinetic monitor config")
	}
	ctrls, seen := map[string][]byte{}, map[string]struct{}{}
	for id, key := range cfg.Controllers {
		if !validID(id) || len(key) != 32 {
			return nil, fmt.Errorf("invalid controller")
		}
		if _, dup := seen[string(key)]; dup {
			return nil, fmt.Errorf("invalid controller")
		}
		seen[string(key)] = struct{}{}
		b := make([]byte, 32)
		copy(b, key)
		ctrls[id] = b
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = PollInterval
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	m := &Monitor{dir: cfg.Dir, sessionID: cfg.SessionID, sessionEpoch: cfg.SessionEpoch, controllers: ctrls, poll: cfg.PollInterval, now: cfg.Now}
	if st, err := ReadState(cfg.Dir, cfg.SessionID, ctrls); err == nil {
		m.state = &st
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return m, nil
}
func (m *Monitor) StartupCheck() error {
	if m.state != nil && m.state.SessionID == m.sessionID && m.state.RevokedThroughEpoch >= m.sessionEpoch {
		return ErrPreviouslyRevoked
	}
	cl, _, _ := m.classifyCommand()
	return map[int]error{classRevoke: ErrPreviouslyRevoked, classInvalid: ErrControlInvalid, classUnavailable: ErrControlUnavailable}[cl]
}
func (m *Monitor) Run(ctx context.Context, stop func(Stop)) error {
	tick := time.NewTicker(m.poll)
	defer tick.Stop()
	for {
		cl, st, _ := m.classifyCommand()
		if cl == classRevoke || cl == classUnavailable || cl == classInvalid {
			stop(st)
			return map[int]error{classUnavailable: ErrControlUnavailable, classInvalid: ErrControlInvalid}[cl]
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func (m *Monitor) WriteState(stop Stop) error {
	if err := validateSubdir(m.dir, "state", true); err != nil {
		return err
	}
	epoch := stop.Command.RevokeThroughEpoch
	if existing, err := ReadState(m.dir, m.sessionID, m.controllers); err == nil && existing.RevokedThroughEpoch > epoch {
		epoch = existing.RevokedThroughEpoch
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	st := State{SchemaVersion: SchemaVersion, SessionID: stop.Command.SessionID, RevokedThroughEpoch: epoch, CommandID: stop.Command.CommandID, ControllerID: stop.Command.ControllerID, Reason: stop.Command.Reason, ObservedAt: stop.ObservedAt.UTC().Format(time.RFC3339Nano), ResultingState: stop.ResultingState, RequestSHA256: stop.RequestSHA256}
	err := SignState(&st, m.controllers[st.ControllerID])
	data, err2 := json.Marshal(st)
	if err != nil || err2 != nil {
		if err == nil {
			err = err2
		}
		return err
	}
	if err := atomicWrite(filepath.Join(m.dir, "state"), StatePath(m.dir, m.sessionID), append(data, '\n')); err != nil {
		return err
	}
	m.state = &st
	return nil
}

const classNone, classStale, classRevoke, classInvalid, classUnavailable = 0, 1, 2, 3, 4

func (m *Monitor) classifyCommand() (int, Stop, error) {
	now := m.now().UTC()
	fail := func(res, reason string) Stop {
		return Stop{Command: Command{SessionID: m.sessionID, Reason: reason}, ObservedAt: now, ResultingState: res}
	}
	if ValidateControlDir(m.dir) != nil || validateSubdir(m.dir, "commands", false) != nil {
		return classUnavailable, fail("contained_control_unavailable", "kill-switch control channel unavailable"), nil
	}
	raw, err := readControlFile(CommandPath(m.dir, m.sessionID))
	if errors.Is(err, os.ErrNotExist) {
		return classNone, Stop{}, nil
	}
	var cmd Command
	if err != nil || decodeControl(raw, &cmd) != nil || cmd.SessionID != m.sessionID || VerifyCommand(cmd, m.controllers[cmd.ControllerID]) != nil {
		return classInvalid, fail("contained_control_invalid", "kill-switch control channel invalid"), nil
	}
	if cmd.RevokeThroughEpoch < m.sessionEpoch {
		return classStale, Stop{}, nil
	}
	sum := sha256.Sum256(raw)
	return classRevoke, Stop{Command: cmd, RequestSHA256: hex.EncodeToString(sum[:]), ObservedAt: now, ResultingState: "revoked_contained"}, nil
}
func macFields(ctx string, fields ...string) []byte {
	var b bytes.Buffer
	for _, s := range append([]string{ctx}, fields...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		b.Write(n[:])
		b.WriteString(s)
	}
	return b.Bytes()
}
func validateCommand(c Command, sig bool) error {
	if c.SchemaVersion != SchemaVersion || !isLowerHex(c.CommandID, 32) || !validID(c.SessionID) || c.RevokeThroughEpoch < 1 || !validID(c.ControllerID) || !validReason(c.Reason) || (sig && !isLowerHex(c.Signature, 64)) {
		return fmt.Errorf("invalid kinetic command")
	}
	return nil
}
func validateState(s State, sig bool) error {
	if s.SchemaVersion != SchemaVersion || !validID(s.SessionID) || s.RevokedThroughEpoch < 1 || !isLowerHex(s.CommandID, 32) || !validID(s.ControllerID) || !validReason(s.Reason) || s.ObservedAt == "" || s.ResultingState == "" || !isLowerHex(s.RequestSHA256, 64) || (sig && !isLowerHex(s.Signature, 64)) {
		return fmt.Errorf("invalid kinetic state")
	}
	return nil
}
func decodeControl(raw []byte, dest any) error {
	if err := rejectDupDec(json.NewDecoder(bytes.NewReader(raw))); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(dest) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("invalid control JSON")
	}
	return nil
}
func rejectDupDec(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			ks, _ := k.(string)
			if seen[ks] {
				return fmt.Errorf("duplicate JSON key %q", ks)
			}
			seen[ks] = true
		}
		if err := rejectDupDec(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
func readControlFile(path string) ([]byte, error) { return readOwnedFile(path, MaxControlBytes, 0o600) }
func readOwnedFile(path string, max int64, perm os.FileMode) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != perm || st.Size() > max || requireOwner(st) != nil {
		return nil, fmt.Errorf("invalid control file")
	}
	return b, nil
}
func atomicWrite(dir, final string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error { _ = f.Close(); _ = os.Remove(tmp); return err }
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := fileSync(f); err != nil {
		return fail(err)
	}
	_ = f.Close()
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return dirSync(dir)
}
func validateSubdir(parent, name string, create bool) error {
	p := filepath.Join(parent, name)
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = os.Mkdir(p, 0o700); err == nil {
			if err = dirSync(parent); err == nil {
				st, err = os.Lstat(p)
			}
		} else if errors.Is(err, os.ErrExist) {
			// A concurrent writer created the subdirectory between our Lstat and
			// Mkdir. Re-stat it and fall through to the same validation, instead
			// of failing this write on a lost creation race.
			st, err = os.Lstat(p)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("missing control subdirectory")
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("invalid control subdirectory")
	}
	return requireOwner(st)
}
