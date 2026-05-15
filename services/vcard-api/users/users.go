// Package users — minimal user store keyed by Apple's stable sub claim.
// We store the user's name and email (could be the relay address) for
// display only; the source of truth for identity is always Apple.
package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("user not found")

type User struct {
	ID       string `json:"id"`
	AppleSub string `json:"-"` // never returned to clients
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
}

type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

// Upsert returns an existing user with the matching apple_sub or creates
// one. The (optional) name/email are filled on first sight; subsequent
// SIWA flows only return them if Apple shipped them in the token (Apple
// strips name/email after the first sign-in).
func (r *Repo) Upsert(ctx context.Context, appleSub, name, email string) (*User, error) {
	// Try the fast path — already exists.
	const selQ = `SELECT id, COALESCE(name, ''), COALESCE(email, '') FROM users WHERE apple_sub = $1`
	var u User
	u.AppleSub = appleSub
	if err := r.db.QueryRowContext(ctx, selQ, appleSub).Scan(&u.ID, &u.Name, &u.Email); err == nil {
		// If the prior insert went through without name/email but Apple
		// shipped them now (rare — happens if the user revokes + re-grants),
		// patch the row.
		if (u.Name == "" && name != "") || (u.Email == "" && email != "") {
			_, _ = r.db.ExecContext(ctx,
				`UPDATE users SET name = COALESCE(NULLIF($1, ''), name), email = COALESCE(NULLIF($2, ''), email) WHERE id = $3`,
				name, email, u.ID)
			if name != "" {
				u.Name = name
			}
			if email != "" {
				u.Email = email
			}
		}
		return &u, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user select: %w", err)
	}

	// Insert path.
	const insQ = `
		INSERT INTO users (apple_sub, name, email)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''))
		ON CONFLICT (apple_sub) DO UPDATE SET name = COALESCE(users.name, EXCLUDED.name), email = COALESCE(users.email, EXCLUDED.email)
		RETURNING id, COALESCE(name, ''), COALESCE(email, '')`
	if err := r.db.QueryRowContext(ctx, insQ, appleSub, name, email).Scan(&u.ID, &u.Name, &u.Email); err != nil {
		return nil, fmt.Errorf("user upsert: %w", err)
	}
	return &u, nil
}

// GetByID returns a single user by primary key.
func (r *Repo) GetByID(ctx context.Context, id string) (*User, error) {
	const q = `SELECT id, apple_sub, COALESCE(name, ''), COALESCE(email, '') FROM users WHERE id = $1`
	var u User
	if err := r.db.QueryRowContext(ctx, q, id).Scan(&u.ID, &u.AppleSub, &u.Name, &u.Email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("user get: %w", err)
	}
	return &u, nil
}
