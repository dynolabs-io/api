// pass-signer: signs Apple .pkpass + Google Wallet JWT.
// Holds the Pass Type ID .p12 (Apple) and service account .json (Google) as
// mounted secrets. Other services request signed passes over HTTP.
//
// Stub-mode: when PASS_SIGNER_STUB=1 the service responds 503 to /pass/* but
// /healthz still returns 200 — lets us deploy before Apple cert is available.
package main

import (
	"context"
	"encoding/json"
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

	stub := os.Getenv("PASS_SIGNER_STUB") == "1"

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("pass-signer", version))
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true,"stub":` + map[bool]string{true: "true", false: "false"}[stub] + `}`))
	})

	mux.HandleFunc("POST /pass/apple", func(w http.ResponseWriter, r *http.Request) {
		if stub {
			http.Error(w, `{"error":"stub-mode: Apple Pass Type ID cert not yet provisioned"}`, http.StatusServiceUnavailable)
			return
		}
		// TODO(phase-6): assemble .pkpass, sign with Pass Type ID .p12, return zip.
		_ = json.NewEncoder(w).Encode(map[string]string{"todo": "phase-6"})
	})

	mux.HandleFunc("POST /pass/google", func(w http.ResponseWriter, r *http.Request) {
		if stub {
			http.Error(w, `{"error":"stub-mode: Google Wallet issuer not yet provisioned"}`, http.StatusServiceUnavailable)
			return
		}
		// TODO(phase-6): build GenericObject + sign JWT with service-account key.
		_ = json.NewEncoder(w).Encode(map[string]string{"todo": "phase-6"})
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("pass-signer listening", "addr", addr, "version", version, "stub", stub)
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
