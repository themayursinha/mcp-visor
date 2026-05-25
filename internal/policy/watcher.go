package policy

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	mu       sync.RWMutex
	policy   *Policy
	registry *Registry

	path   string
	logger *slog.Logger

	fw   *fsnotify.Watcher
	done chan struct{}
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
		fw.Close()
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

	w.mu.Lock()
	w.policy = pol
	w.registry = NewRegistry(pol)
	w.mu.Unlock()

	w.logger.Info("policy hot-reloaded",
		"path", w.path,
		"default_action", pol.DefaultAction,
		"servers", len(pol.Servers),
		"chain_rules", len(pol.ToolChains),
	)
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
	w.fw.Close()
	w.logger.Info("policy watcher stopped", "path", w.path)
}
