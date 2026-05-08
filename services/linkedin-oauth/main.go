// linkedin-oauth: handles the OAuth 2.0 Authorization Code flow for LinkedIn.
// Mobile app opens /authorize → LinkedIn → callback /callback → token exchange
// → fetch r_liteprofile + r_emailaddress → publish to NATS → close session.
//
// Stub-mode: until LinkedIn OAuth app is created at developer.linkedin.com,
// /authorize returns 503. /healthz still 200 so the pod stays in rotation.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dynolabs-io/api/shared/health"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	stub := os.Getenv("LINKEDIN_CLIENT_ID") == ""

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("linkedin-oauth", version))
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true,"stub":` + map[bool]string{true: "true", false: "false"}[stub] + `}`))
	})

	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		if stub {
			http.Error(w, `{"error":"stub-mode: LinkedIn OAuth app not yet configured"}`, http.StatusServiceUnavailable)
			return
		}
		// TODO(phase-6): build LinkedIn auth URL, set state cookie, 302 redirect.
		http.Error(w, `{"error":"not-implemented"}`, http.StatusNotImplemented)
	})

	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		if stub {
			http.Error(w, `{"error":"stub-mode"}`, http.StatusServiceUnavailable)
			return
		}
		// TODO(phase-6): exchange code → token, fetch profile, publish NATS event.
		http.Error(w, `{"error":"not-implemented"}`, http.StatusNotImplemented)
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("linkedin-oauth listening", "addr", addr, "version", version, "stub", stub)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
