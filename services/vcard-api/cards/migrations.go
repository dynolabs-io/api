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
