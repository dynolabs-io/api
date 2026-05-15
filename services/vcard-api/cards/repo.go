package cards

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("card not found")

type Repo struct {
	db *sql.DB
}

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

// genSlug returns a URL-safe 8-char slug from [a-z2-9]. Avoids look-alike
// chars (0/o, 1/l) for verbal sharing. ~10^11 keyspace is plenty for v1.
func genSlug() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	var b [8]byte
	_, _ = rand.Read(b[:])
	out := make([]byte, 8)
	for i, x := range b {
		out[i] = alphabet[int(x)%len(alphabet)]
	}
	return string(out)
}

// Create inserts a new card. Caller may leave Slug empty; we generate one.
func (r *Repo) Create(ctx context.Context, c *Card) error {
	if c.Slug == "" {
		c.Slug = genSlug()
	}
	if c.Template == "" {
		c.Template = "mono"
	}
	if c.Label == "" {
		c.Label = "Work"
	}
	emails, _ := json.Marshal(orEmpty(c.Emails))
	phones, _ := json.Marshal(orEmpty(c.Phones))
	socials, _ := json.Marshal(orEmptySocials(c.Socials))

	const q = `
		INSERT INTO cards (slug, label, name, title, company, emails, phones, socials, photo_url, brand_logo_url, template, custom_color, wallet_style, device_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, created_at, updated_at`
	row := r.db.QueryRowContext(ctx, q,
		c.Slug, c.Label, c.Name, nullable(c.Title), nullable(c.Company),
		emails, phones, socials, nullable(c.PhotoURL), nullable(c.BrandLogoURL),
		c.Template, nullable(c.CustomColor), nullable(c.WalletStyle), nullable(c.DeviceID),
	)
	if err := row.Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return fmt.Errorf("insert card: %w", err)
	}
	return nil
}

func (r *Repo) GetByID(ctx context.Context, id string) (*Card, error) {
	const q = baseSelect + ` WHERE id = $1`
	return r.scanOne(ctx, q, id)
}

func (r *Repo) GetBySlug(ctx context.Context, slug string) (*Card, error) {
	const q = baseSelect + ` WHERE slug = $1`
	return r.scanOne(ctx, q, slug)
}

func (r *Repo) ListByDevice(ctx context.Context, deviceID string) ([]Card, error) {
	const q = baseSelect + ` WHERE device_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list by device: %w", err)
	}
	defer rows.Close()
	var out []Card
	for rows.Next() {
		c, err := scanCard(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// ListByUser returns all cards attached to the given user_id (regardless
// of which device created them). Used by the mobile app on launch when
// the user is signed in.
func (r *Repo) ListByUser(ctx context.Context, userID string) ([]Card, error) {
	const q = baseSelect + ` WHERE user_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list by user: %w", err)
	}
	defer rows.Close()
	var out []Card
	for rows.Next() {
		c, err := scanCard(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// SetUser attaches a single card to the given user_id (used at create
// time when the caller is signed in).
func (r *Repo) SetUser(ctx context.Context, cardID, userID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE cards SET user_id = $1 WHERE id = $2`, userID, cardID)
	if err != nil {
		return fmt.Errorf("set user: %w", err)
	}
	return nil
}

// AttachToUser sets user_id on every card currently attached to the
// given device_id but NOT yet owned by any user. This is the silent
// "claim" path at first sign-in. Returns the affected card IDs so the
// caller can re-fetch them with the new user_id projection.
func (r *Repo) AttachToUser(ctx context.Context, deviceID, userID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`UPDATE cards SET user_id = $1, updated_at = now()
		 WHERE device_id = $2 AND user_id IS NULL
		 RETURNING id`, userID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("attach to user: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ResolveConflict applies one of three resolutions to a slug-collision
// between a local-only card and one already on the user's account.
//
//	"local"   → overwrite the server's card with the local payload.
//	"remote"  → discard the local (no-op on server, mobile drops its copy).
//	"both"    → re-slug the local card with a fresh slug and INSERT as a
//	             new server card owned by user_id.
func (r *Repo) ResolveConflict(ctx context.Context, userID, slug, winner string, local *Card) (*Card, error) {
	switch winner {
	case "remote":
		return r.GetBySlug(ctx, slug)
	case "local":
		// Server card stays at this slug; rewrite fields from local payload.
		existing, err := r.GetBySlug(ctx, slug)
		if err != nil {
			return nil, err
		}
		local.ID = existing.ID
		local.Slug = existing.Slug
		if err := r.Update(ctx, local); err != nil {
			return nil, err
		}
		return local, nil
	case "both":
		// Insert a fresh card with a new slug, owned by the user.
		local.Slug = ""
		local.ID = ""
		local.DeviceID = ""
		local.UserID = userID
		if err := r.Create(ctx, local); err != nil {
			return nil, err
		}
		// Attach user_id via UPDATE (Create doesn't take user_id from struct).
		if _, err := r.db.ExecContext(ctx, `UPDATE cards SET user_id = $1 WHERE id = $2`, userID, local.ID); err != nil {
			return nil, err
		}
		local.UserID = userID
		return local, nil
	default:
		return nil, fmt.Errorf("unknown conflict winner %q", winner)
	}
}

func (r *Repo) Update(ctx context.Context, c *Card) error {
	emails, _ := json.Marshal(orEmpty(c.Emails))
	phones, _ := json.Marshal(orEmpty(c.Phones))
	socials, _ := json.Marshal(orEmptySocials(c.Socials))
	const q = `
		UPDATE cards SET label=$1, name=$2, title=$3, company=$4,
		  emails=$5, phones=$6, socials=$7, photo_url=$8, brand_logo_url=$9,
		  template=$10, custom_color=$11, wallet_style=$12, updated_at=now()
		WHERE id=$13 RETURNING updated_at`
	row := r.db.QueryRowContext(ctx, q,
		c.Label, c.Name, nullable(c.Title), nullable(c.Company),
		emails, phones, socials, nullable(c.PhotoURL), nullable(c.BrandLogoURL),
		c.Template, nullable(c.CustomColor), nullable(c.WalletStyle), c.ID)
	if err := row.Scan(&c.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("update card: %w", err)
	}
	return nil
}

func (r *Repo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cards WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete card: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const baseSelect = `
	SELECT id, slug, label, name,
	       COALESCE(title, ''), COALESCE(company, ''),
	       emails, phones, socials,
	       COALESCE(photo_url, ''), COALESCE(brand_logo_url, ''),
	       template,
	       COALESCE(custom_color, ''), COALESCE(wallet_style, ''),
	       COALESCE(device_id, ''),
	       COALESCE(user_id::text, ''),
	       created_at, updated_at
	FROM cards`

type rowScanner interface {
	Scan(dest ...any) error
}

func (r *Repo) scanOne(ctx context.Context, q string, args ...any) (*Card, error) {
	row := r.db.QueryRowContext(ctx, q, args...)
	c, err := scanCard(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func scanCard(s rowScanner) (*Card, error) {
	var c Card
	var emailsRaw, phonesRaw, socialsRaw []byte
	if err := s.Scan(
		&c.ID, &c.Slug, &c.Label, &c.Name,
		&c.Title, &c.Company,
		&emailsRaw, &phonesRaw, &socialsRaw,
		&c.PhotoURL, &c.BrandLogoURL, &c.Template,
		&c.CustomColor, &c.WalletStyle, &c.DeviceID, &c.UserID,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(emailsRaw, &c.Emails)
	_ = json.Unmarshal(phonesRaw, &c.Phones)
	_ = json.Unmarshal(socialsRaw, &c.Socials)
	if c.Emails == nil {
		c.Emails = []string{}
	}
	if c.Phones == nil {
		c.Phones = []string{}
	}
	if c.Socials == nil {
		c.Socials = []Social{}
	}
	return &c, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptySocials(s []Social) []Social { return orEmpty(s) }
