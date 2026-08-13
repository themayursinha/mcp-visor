package policy

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloadHook observes a policy after a successful atomic reload.
// Hooks must not call Reload() reentrantly.
type ReloadHook func(newPolicy *Policy)

// ReloadCommitter atomically publishes a policy with dependent runtime surfaces.
// It must invoke publish before returning. At most one committer may be registered.
type ReloadCommitter func(newPolicy *Policy, publish func())

type Watcher struct {
	mu        sync.RWMutex
	policy    *Policy
	registry  *Registry
	hooks     []ReloadHook
	committer ReloadCommitter

	path   string
	logger *slog.Logger

	fw   *fsnotify.Watcher
	done chan struct{}

	// reloadStall is a test-only seam invoked immediately before the locked
	// committer decision during reload. Production leaves it nil.
	reloadStall func()
}

func NewWatcher(path string) (*Watcher, error) {
	pol, err := LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load initial policy: %w", err)
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create file watcher: %w", err)
	}

	if err := fw.Add(path); err != nil {
		_ = fw.Close()
		return nil, fmt.Errorf("watch policy file '%s': %w", path, err)
	}

	w := &Watcher{
		policy:   pol,
		registry: NewRegistry(pol),
		path:     path,
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		fw:   fw,
		done: make(chan struct{}),
	}

	w.logger.Info("policy watcher started",
		"path", path,
		"default_action", pol.DefaultAction,
	)

	go w.loop()
	return w, nil
}

func (w *Watcher) loop() {
	const debounceInterval = 2 * time.Second

	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}

	var pending bool
	var pendingNeedsReload bool

	for {
		select {
		case <-w.done:
			return

		case event, ok := <-w.fw.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				if !pending {
					pending = true
					debounce.Reset(debounceInterval)
				}
				pendingNeedsReload = true
			}
			if event.Has(fsnotify.Remove) {
				w.logger.Warn("policy file removed, waiting for re-creation", "path", w.path)
				if err := w.fw.Add(w.path); err != nil {
					w.logger.Error("failed to re-watch policy file", "path", w.path, "error", err)
				}
			}

		case err, ok := <-w.fw.Errors:
			if !ok {
				return
			}
			w.logger.Error("policy watcher error", "error", err)

		case <-debounce.C:
			pending = false
			if pendingNeedsReload {
				pendingNeedsReload = false
				w.reload()
			}
		}
	}
}

func (w *Watcher) reload() {
	pol, err := LoadFile(w.path)
	if err != nil {
		w.logger.Error("policy hot-reload failed, keeping current policy",
			"path", w.path,
			"error", err,
		)
		return
	}

	reg := NewRegistry(pol)

	w.mu.RLock()
	stall := w.reloadStall
	w.mu.RUnlock()

	// Test seam: hold an in-flight reload that began before committer
	// registration so the locked decision below can observe a committer
	// installed concurrently (or a completed nil-committer publish can be
	// reconciled after SetReloadCommitter returns).
	if stall != nil {
		stall()
	}

	var publishOnce sync.Once
	publish := func() {
		publishOnce.Do(func() {
			w.mu.Lock()
			w.policy = pol
			w.registry = reg
			w.mu.Unlock()
		})
	}

	// Hold the lock across the nil-committer publish decision so:
	// 1. an in-flight reload re-reads a committer registered after LoadFile,
	// 2. SetReloadCommitter cannot observe a committed generation that
	//    bypassed the atomic runtime transaction.
	w.mu.Lock()
	committer := w.committer
	hooks := append([]ReloadHook(nil), w.hooks...)
	if committer == nil {
		w.policy = pol
		w.registry = reg
		w.mu.Unlock()
	} else {
		w.mu.Unlock()
		committer(pol, publish)
	}

	for _, hook := range hooks {
		if hook != nil {
			hook(pol)
		}
	}

	w.logger.Info("policy hot-reloaded",
		"path", w.path,
		"default_action", pol.DefaultAction,
		"servers", len(pol.Servers),
		"chain_rules", len(pol.ToolChains),
	)
}

// OnReload registers a hook invoked after each successful reload.
// Hooks run outside the watcher lock so they may call Current().
func (w *Watcher) OnReload(hook ReloadHook) {
	if hook == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hooks = append(w.hooks, hook)
}

// SetReloadCommitter installs the single transaction responsible for publishing
// the watcher snapshot with dependent runtime surfaces. It is configured during
// proxy construction, before the watcher is used for live reloads. It returns
// the watcher's currently published policy so the caller can reconcile runtime
// surfaces that may already have advanced via a nil-committer publish.
func (w *Watcher) SetReloadCommitter(committer ReloadCommitter) *Policy {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.committer = committer
	return w.policy
}

// SetReloadStallForTest installs a synchronous stall invoked during reload.
// Production code must leave this nil; it exists so tests can hold an
// in-flight reload across committer registration without sleeps.
func (w *Watcher) SetReloadStallForTest(fn func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reloadStall = fn
}

func (w *Watcher) Reload() {
	w.reload()
}

func (w *Watcher) Current() (*Policy, *Registry) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.policy, w.registry
}

func (w *Watcher) Policy() *Policy {
	pol, _ := w.Current()
	return pol
}

func (w *Watcher) Registry() *Registry {
	_, reg := w.Current()
	return reg
}

func (w *Watcher) Close() {
	close(w.done)
	_ = w.fw.Close()
	w.logger.Info("policy watcher stopped", "path", w.path)
}
