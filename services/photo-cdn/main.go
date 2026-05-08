// photo-cdn: S3-backed avatar storage + serving at cdn.dynolabs.io.
// Upload endpoint authenticated via short-lived signed URL issued by vcard-api.
// Serve endpoint is anonymous-readable (vCard recipients fetch the photo).
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

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("photo-cdn", version))
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
	})

	mux.HandleFunc("POST /p/{slug}", func(w http.ResponseWriter, r *http.Request) {
		// TODO(phase-6): validate signed URL, stream to S3/MinIO, return public URL.
		http.Error(w, `{"error":"not-implemented"}`, http.StatusNotImplemented)
	})

	mux.HandleFunc("GET /p/{slug}", func(w http.ResponseWriter, r *http.Request) {
		// TODO(phase-6): proxy from S3/MinIO with cache headers.
		http.Error(w, `{"error":"not-implemented"}`, http.StatusNotImplemented)
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("photo-cdn listening", "addr", addr, "version", version)
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
