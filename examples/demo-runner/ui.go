package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	_ "embed"
)

//go:embed proof.html
var proofHTML []byte

type proofServer struct {
	auditLog     string
	observeLog   string
	sequenceDone atomic.Bool
}

func (ps *proofServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(proofHTML)
}

func (ps *proofServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := readSnapshot(ps.auditLog, ps.observeLog)
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
		return
	}
	if ps.sequenceDone.Load() {
		snap.Integrity = proofIntegrity(snap)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(snap)
}

func runUI(addr string) error {
	if err := validateListenAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	if err := validateListenAddr(ln.Addr().String()); err != nil {
		return err
	}

	sess, err := prepareDemo()
	if err != nil {
		return err
	}
	defer sess.cleanup()

	ps := &proofServer{auditLog: sess.auditLog, observeLog: sess.observeLog}
	mux := http.NewServeMux()
	mux.HandleFunc("/", ps.handleIndex)
	mux.HandleFunc("/api/snapshot", ps.handleSnapshot)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()

	u := url.URL{Scheme: "http", Host: ln.Addr().String()}
	fmt.Fprintf(os.Stderr, "Proof Console: %s\n", u.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	driveErr := make(chan error, 1)
	go func() {
		driveErr <- sess.driveSequence(false, time.Second)
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-driveErr:
		if err != nil {
			return err
		}
		ps.sequenceDone.Store(true)
		<-ctx.Done()
		return nil
	}
}
