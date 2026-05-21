// vcard-api: HTTP service for cards CRUD + slug resolution.
// CAP-AP design — eventual consistency via NATS replication (Phase 6.5).
// PostgreSQL is the source-of-truth.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dynolabs-io/api/services/vcard-api/auth"
	"github.com/dynolabs-io/api/services/vcard-api/cards"
	"github.com/dynolabs-io/api/services/vcard-api/enrich"
	"github.com/dynolabs-io/api/services/vcard-api/leads"
	"github.com/dynolabs-io/api/services/vcard-api/scans"
	"github.com/dynolabs-io/api/services/vcard-api/users"
	"github.com/dynolabs-io/api/services/vcard-api/wallet"
	"github.com/dynolabs-io/api/shared/health"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// version is injected at link time via -ldflags "-X main.version=<sha>".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("vcard-api", version))

	// Postgres is wired in if DATABASE_URL is set. If absent (e.g. unit-test
	// runs of this binary), we skip wiring the cards endpoints and
	// /readyz reports DB:disabled — the pod still passes liveness.
	dbURL := getenv("DATABASE_URL", "")
	var db *sql.DB
	if dbURL != "" {
		var err error
		db, err = openDB(dbURL)
		if err != nil {
			slog.Error("postgres open failed", "err", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := cards.Migrate(ctx, db); err != nil {
			cancel()
			slog.Error("migrate failed", "err", err)
			os.Exit(1)
		}
		cancel()

		// Sign-in with Apple: optional. Bundle ID identifies the iOS
		// app; HMAC secret signs our own session tokens (32 bytes hex).
		// Falls back to an ephemeral secret with a warning so the pod
		// boots even before the K8s secret is wired — auth simply won't
		// survive a pod restart in that fallback.
		bundleID := getenv("APPLE_BUNDLE_ID", "io.dynolabs.vcard")
		secretHex := getenv("VCARD_HMAC_SECRET", "")
		var secret []byte
		if secretHex != "" {
			s, err := hex.DecodeString(secretHex)
			if err != nil {
				slog.Error("VCARD_HMAC_SECRET must be hex", "err", err)
				os.Exit(1)
			}
			secret = s
		} else {
			secret = make([]byte, 32)
			_, _ = rand.Read(secret)
			slog.Warn("VCARD_HMAC_SECRET not set — using ephemeral secret; sessions WILL invalidate on pod restart",
				"hint", "set VCARD_HMAC_SECRET to 64 hex chars (openssl rand -hex 32)")
		}
		verifier := auth.New(bundleID, secret)
		usersRepo := users.NewRepo(db)
		cardsRepo := cards.NewRepo(db)
		(&cards.Handlers{Repo: cardsRepo, AuthVerify: verifier.UserIDFromBearer}).Mount(mux)
		(&auth.Handlers{V: verifier, Users: usersRepo, Cards: cardsRepo}).Mount(mux)
		scansRepo := scans.NewRepo(db)
		(&scans.Handlers{Repo: scansRepo, AuthVerify: verifier.UserIDFromBearer}).Mount(mux)
		leadsRepo := leads.NewRepo(db)
		(&leads.Handlers{Repo: leadsRepo, AuthVerify: verifier.UserIDFromBearer}).Mount(mux)
		// Apple Wallet web-service. PassBuilder is a passthrough to
		// pass-signer's /pass/apple endpoint — when iOS Wallet asks for
		// a refreshed pass we proxy the call.
		walletRepo := wallet.NewRepo(db)
		walletToken := getenv("WALLET_WEBSERVICE_TOKEN", "")
		(&wallet.Handlers{
			Repo:        walletRepo,
			AuthToken:   walletToken,
			PassBuilder: wallet.PassSignerBuilder(getenv("PASS_SIGNER_URL", "http://pass-signer.dynolabs.svc")),
		}).Mount(mux)
		// Apollo.io email-enrichment — fills title+company gap that
		// LinkedIn OIDC leaves blank after sign-in. Graceful-skip
		// when APOLLO_API_KEY is unset (returns empty fields).
		apolloClient := enrich.NewClient(getenv("APOLLO_API_KEY", ""))
		// LinkedIn vanity-page enrichment via the iogrid residential
		// proxy (SOCKS5+TLS). Graceful-skip when any of
		// IOGRID_API_KEY / IOGRID_WORKSPACE / IOGRID_PROXY_URL is unset.
		linkedInClient := enrich.LinkedInFromEnv()
		(&enrich.Handlers{
			Client:     apolloClient,
			LinkedIn:   linkedInClient,
			AuthVerify: verifier.UserIDFromBearer,
		}).Mount(mux)
		slog.Info("postgres + cards + auth + scans + leads + wallet + enrich mounted", "bundle", bundleID)
	} else {
		slog.Warn("DATABASE_URL not set — running without persistence")
	}

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if db != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := db.PingContext(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"ready":false,"db":"down"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("vcard-api listening", "addr", addr, "version", version)
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
	if db != nil {
		_ = db.Close()
	}
}

func openDB(url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return nil, err
	}
	return db, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
