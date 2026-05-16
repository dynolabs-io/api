package cards

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrate creates the schema on first startup. Idempotent — uses
// IF NOT EXISTS so a v1 cluster can boot repeatedly without a separate
// migration runner. v1.1 will move to a real migration tool (golang-migrate).
func Migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS cards (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			slug         TEXT UNIQUE NOT NULL,
			label        TEXT NOT NULL DEFAULT 'Work',
			name         TEXT NOT NULL,
			title        TEXT,
			company      TEXT,
			emails       JSONB NOT NULL DEFAULT '[]'::jsonb,
			phones       JSONB NOT NULL DEFAULT '[]'::jsonb,
			socials      JSONB NOT NULL DEFAULT '[]'::jsonb,
			photo_url    TEXT,
			template     TEXT NOT NULL DEFAULT 'mono',
			custom_color TEXT,
			device_id    TEXT,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS cards_device_idx ON cards(device_id)`,
		`ALTER TABLE cards ADD COLUMN IF NOT EXISTS wallet_style TEXT`,
		`ALTER TABLE cards ADD COLUMN IF NOT EXISTS brand_logo_url TEXT`,
		// Optional Apple-Sign-In account ownership. user_id NULL = the
		// card is anonymous, device-bound (legacy & first-launch path).
		// user_id SET = the card syncs across all the user's devices.
		`CREATE TABLE IF NOT EXISTS users (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			apple_sub   TEXT UNIQUE NOT NULL,
			name        TEXT,
			email       TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE cards ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL`,
		`CREATE INDEX IF NOT EXISTS cards_user_idx ON cards(user_id)`,
		// "scans" — the rolodex. One row per scan event by a Dynolabs user.
		// scanner_user_id NULL when the scanner is anonymous (mobile keeps
		// the row locally only). target_slug is the public slug of the
		// scanned card — owner is found via cards.slug lookup.
		// notes / tags / location / event_name / scanned_at all per-scan.
		`CREATE TABLE IF NOT EXISTS scans (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scanner_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			target_slug     TEXT NOT NULL,
			notes           TEXT,
			tags            JSONB NOT NULL DEFAULT '[]'::jsonb,
			lat             DOUBLE PRECISION,
			lon             DOUBLE PRECISION,
			place_name      TEXT,
			event_name      TEXT,
			scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS scans_scanner_idx ON scans(scanner_user_id, scanned_at DESC)`,
		`CREATE INDEX IF NOT EXISTS scans_target_idx ON scans(target_slug, scanned_at DESC)`,
		// "leads" — visitors to dynolabs.io/c/<slug> who used the
		// "request callback" form. Belongs to the card OWNER via the
		// slug lookup (cards.slug → cards.user_id).
		`CREATE TABLE IF NOT EXISTS leads (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			target_slug  TEXT NOT NULL,
			from_name    TEXT,
			from_email   TEXT,
			from_phone   TEXT,
			message      TEXT,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS leads_target_idx ON leads(target_slug, created_at DESC)`,
		// "scan_events" — anonymous fact table: every hit on /v/<slug>
		// or web profile page view counts here. Used for Inbox reach
		// analytics. Lightweight: ip_geo (city), ua_family, no PII.
		`CREATE TABLE IF NOT EXISTS scan_events (
			id          BIGSERIAL PRIMARY KEY,
			target_slug TEXT NOT NULL,
			kind        TEXT NOT NULL,  -- 'vcf' | 'profile' | 'pkpass'
			city        TEXT,
			country     TEXT,
			ua_family   TEXT,
			occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS scan_events_target_idx ON scan_events(target_slug, occurred_at DESC)`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: %q: %w", firstLine(s), err)
		}
	}
	return nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
		if i > 60 {
			return s[:60] + "..."
		}
	}
	return s
}
