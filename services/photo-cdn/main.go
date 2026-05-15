// photo-cdn: serves and accepts profile photos for Dynolabs vCards.
//
// MVP auth model: open writes (any client can PUT to /p/<slug>) on the
// theory that slugs are 8 random chars from [a-z2-9] = ~852B keyspace
// and only the device that owns a slug knows it from the API response.
// Real device-bound HMAC signing comes in v1.1.

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dynolabs-io/api/shared/health"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var version = "dev"

const maxPhotoSize = 8 * 1024 * 1024 // 8 MiB

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	endpoint := strings.TrimPrefix(strings.TrimPrefix(getenv("S3_ENDPOINT", "http://minio.dynolabs.svc:9000"), "http://"), "https://")
	useSSL := strings.HasPrefix(getenv("S3_ENDPOINT", ""), "https://")
	bucket := getenv("S3_BUCKET", "vcard-photos")
	accessKey := getenv("S3_ACCESS_KEY", "dynolabs-admin")
	secretKey := getenv("S3_SECRET_KEY", "")

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		slog.Error("minio client init failed", "err", err)
		os.Exit(1)
	}

	// Ensure bucket exists. The MinIO admin we mounted has full access.
	bctx, bcancel := context.WithTimeout(context.Background(), 10*time.Second)
	exists, err := mc.BucketExists(bctx, bucket)
	bcancel()
	if err != nil {
		slog.Warn("bucket-exists check failed (will retry on first request)", "err", err)
	} else if !exists {
		mctx, mcancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := mc.MakeBucket(mctx, bucket, minio.MakeBucketOptions{}); err != nil {
			slog.Warn("create bucket failed", "bucket", bucket, "err", err)
		} else {
			slog.Info("bucket created", "bucket", bucket)
		}
		mcancel()
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("photo-cdn", version))
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
	})

	mux.HandleFunc("POST /p/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !validSlug(slug) {
			http.Error(w, `{"error":"invalid slug"}`, http.StatusBadRequest)
			return
		}
		// Read full body up to maxPhotoSize (image upload)
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPhotoSize+1))
		if err != nil {
			http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
			return
		}
		if len(body) > maxPhotoSize {
			http.Error(w, `{"error":"photo larger than 8 MiB"}`, http.StatusRequestEntityTooLarge)
			return
		}
		ctype := http.DetectContentType(body)
		if !strings.HasPrefix(ctype, "image/") {
			http.Error(w, fmt.Sprintf(`{"error":"not an image: %s"}`, ctype), http.StatusBadRequest)
			return
		}
		objKey := slug + ".jpg" // we standardize on .jpg for vCard compatibility
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		_, err = mc.PutObject(ctx, bucket, objKey,
			bytes.NewReader(body), int64(len(body)),
			minio.PutObjectOptions{
				ContentType:  ctype,
				CacheControl: "public, max-age=86400",
			})
		if err != nil {
			slog.Error("minio put failed", "slug", slug, "err", err)
			http.Error(w, `{"error":"upload failed"}`, http.StatusBadGateway)
			return
		}
		// Public URL for the saved object.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"url":"https://cdn.dynolabs.io/p/%s"}`, slug)
	})

	mux.HandleFunc("GET /p/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !validSlug(slug) {
			http.Error(w, `{"error":"invalid slug"}`, http.StatusBadRequest)
			return
		}
		objKey := slug + ".jpg"
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		obj, err := mc.GetObject(ctx, bucket, objKey, minio.GetObjectOptions{})
		if err != nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		defer obj.Close()
		stat, err := obj.Stat()
		if err != nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", stat.ContentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size))
		_, _ = io.Copy(w, obj)
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("photo-cdn listening", "addr", addr, "version", version, "bucket", bucket, "endpoint", endpoint)
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

func validSlug(s string) bool {
	// Slugs are server-issued base32-like strings. We also accept a
	// "<slug>-brand" suffix for brand-logo uploads — same security
	// model (no traversal, no shell metachars), one optional dash.
	base := s
	if strings.HasSuffix(s, "-brand") {
		base = strings.TrimSuffix(s, "-brand")
	}
	if len(base) < 4 || len(base) > 16 {
		return false
	}
	for _, c := range base {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '9')) {
			return false
		}
	}
	return true
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
