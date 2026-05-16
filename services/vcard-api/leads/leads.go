// Package leads — visitors to dynolabs.io/c/<slug> who fill the
// "request callback" form. Owner sees them in the Inbox tab.
//
// Endpoints:
//
//	POST /v1/leads               PUBLIC — visitor submits form
//	GET  /v1/leads               AUTH   — list leads for my cards
package leads

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var ErrNotFound = errors.New("lead not found")

type Lead struct {
	ID         string    `json:"id"`
	TargetSlug string    `json:"targetSlug"`
	FromName   string    `json:"fromName,omitempty"`
	FromEmail  string    `json:"fromEmail,omitempty"`
	FromPhone  string    `json:"fromPhone,omitempty"`
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

func (r *Repo) Create(ctx context.Context, l *Lead) error {
	const q = `
		INSERT INTO leads (target_slug, from_name, from_email, from_phone, message)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''))
		RETURNING id, created_at`
	return r.db.QueryRowContext(ctx, q, l.TargetSlug, l.FromName, l.FromEmail, l.FromPhone, l.Message).
		Scan(&l.ID, &l.CreatedAt)
}

// ListForUser returns leads on cards owned by the user.
func (r *Repo) ListForUser(ctx context.Context, userID string) ([]Lead, error) {
	const q = `
		SELECT l.id, l.target_slug,
		       COALESCE(l.from_name, ''), COALESCE(l.from_email, ''),
		       COALESCE(l.from_phone, ''), COALESCE(l.message, ''),
		       l.created_at
		FROM leads l
		JOIN cards c ON c.slug = l.target_slug
		WHERE c.user_id = $1
		ORDER BY l.created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list leads: %w", err)
	}
	defer rows.Close()
	var out []Lead
	for rows.Next() {
		var l Lead
		if err := rows.Scan(&l.ID, &l.TargetSlug, &l.FromName, &l.FromEmail, &l.FromPhone, &l.Message, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

type Handlers struct {
	Repo       *Repo
	AuthVerify func(r *http.Request) string
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/leads", h.create)
	mux.HandleFunc("GET /v1/leads", h.list)
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	var l Lead
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(l.TargetSlug) == "" {
		writeErr(w, http.StatusBadRequest, "targetSlug required")
		return
	}
	// At least one contact path needed.
	if l.FromEmail == "" && l.FromPhone == "" {
		writeErr(w, http.StatusBadRequest, "fromEmail or fromPhone required")
		return
	}
	if err := h.Repo.Create(r.Context(), &l); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, l)
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	uid := ""
	if h.AuthVerify != nil {
		uid = h.AuthVerify(r)
	}
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	out, err := h.Repo.ListForUser(r.Context(), uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []Lead{}
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
