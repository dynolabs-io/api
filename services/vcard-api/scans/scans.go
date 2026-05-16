// Package scans — server-side rolodex storage. Each row represents
// one scan event by a signed-in user. Anonymous scanners keep their
// rolodex locally only (mobile AsyncStorage) — nothing is sent.
//
// Endpoints (all require Bearer auth):
//
//	POST   /v1/scans         create a scan record
//	GET    /v1/scans         list the user's scans, newest first
//	PATCH  /v1/scans/{id}    update notes/tags/etc on an existing scan
//	DELETE /v1/scans/{id}    delete a scan
//	GET    /v1/scans/inbox   reach analytics + signed-in scanners of THIS user's cards
package scans

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

var ErrNotFound = errors.New("scan not found")

type Scan struct {
	ID         string    `json:"id"`
	TargetSlug string    `json:"targetSlug"`
	Notes      string    `json:"notes,omitempty"`
	Tags       []string  `json:"tags"`
	Lat        *float64  `json:"lat,omitempty"`
	Lon        *float64  `json:"lon,omitempty"`
	PlaceName  string    `json:"placeName,omitempty"`
	EventName  string    `json:"eventName,omitempty"`
	ScannedAt  time.Time `json:"scannedAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

func (r *Repo) Create(ctx context.Context, userID string, s *Scan) error {
	tags, _ := json.Marshal(orEmpty(s.Tags))
	const q = `
		INSERT INTO scans (scanner_user_id, target_slug, notes, tags, lat, lon, place_name, event_name, scanned_at)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), COALESCE($9, now()))
		RETURNING id, scanned_at, created_at, updated_at`
	var scannedAt *time.Time
	if !s.ScannedAt.IsZero() {
		scannedAt = &s.ScannedAt
	}
	return r.db.QueryRowContext(ctx, q,
		userID, s.TargetSlug, s.Notes, tags, s.Lat, s.Lon, s.PlaceName, s.EventName, scannedAt,
	).Scan(&s.ID, &s.ScannedAt, &s.CreatedAt, &s.UpdatedAt)
}

func (r *Repo) ListByUser(ctx context.Context, userID string) ([]Scan, error) {
	const q = `
		SELECT id, target_slug, COALESCE(notes, ''), tags, lat, lon,
		       COALESCE(place_name, ''), COALESCE(event_name, ''),
		       scanned_at, created_at, updated_at
		FROM scans WHERE scanner_user_id = $1 ORDER BY scanned_at DESC`
	rows, err := r.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var s Scan
		var tagsRaw []byte
		var lat, lon sql.NullFloat64
		if err := rows.Scan(&s.ID, &s.TargetSlug, &s.Notes, &tagsRaw, &lat, &lon,
			&s.PlaceName, &s.EventName, &s.ScannedAt, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tagsRaw, &s.Tags)
		if s.Tags == nil {
			s.Tags = []string{}
		}
		if lat.Valid {
			v := lat.Float64
			s.Lat = &v
		}
		if lon.Valid {
			v := lon.Float64
			s.Lon = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repo) Update(ctx context.Context, userID string, s *Scan) error {
	tags, _ := json.Marshal(orEmpty(s.Tags))
	const q = `
		UPDATE scans SET
			notes      = NULLIF($1, ''),
			tags       = $2,
			place_name = NULLIF($3, ''),
			event_name = NULLIF($4, ''),
			updated_at = now()
		WHERE id = $5 AND scanner_user_id = $6
		RETURNING updated_at`
	if err := r.db.QueryRowContext(ctx, q,
		s.Notes, tags, s.PlaceName, s.EventName, s.ID, userID).Scan(&s.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("update scan: %w", err)
	}
	return nil
}

func (r *Repo) Delete(ctx context.Context, userID, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scans WHERE id = $1 AND scanner_user_id = $2`, id, userID)
	if err != nil {
		return fmt.Errorf("delete scan: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// InboxSummary aggregates "people who scanned MY cards" — for Inbox tab.
type InboxSummary struct {
	TotalScans  int `json:"totalScans"`
	Last7Days   int `json:"last7Days"`
	Last30Days  int `json:"last30Days"`
	UniqueUsers int `json:"uniqueUsers"`
}

// InboxFor returns reach analytics for all cards owned by the user.
func (r *Repo) InboxFor(ctx context.Context, userID string) (*InboxSummary, error) {
	const q = `
		WITH my_slugs AS (SELECT slug FROM cards WHERE user_id = $1)
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE scanned_at > now() - INTERVAL '7 days')  AS d7,
			COUNT(*) FILTER (WHERE scanned_at > now() - INTERVAL '30 days') AS d30,
			COUNT(DISTINCT scanner_user_id) FILTER (WHERE scanner_user_id IS NOT NULL) AS users
		FROM scans WHERE target_slug IN (SELECT slug FROM my_slugs)`
	var s InboxSummary
	if err := r.db.QueryRowContext(ctx, q, userID).Scan(&s.TotalScans, &s.Last7Days, &s.Last30Days, &s.UniqueUsers); err != nil {
		return nil, fmt.Errorf("inbox: %w", err)
	}
	return &s, nil
}

type Handlers struct {
	Repo       *Repo
	AuthVerify func(r *http.Request) string
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/scans", h.create)
	mux.HandleFunc("GET /v1/scans", h.list)
	mux.HandleFunc("PATCH /v1/scans/{id}", h.update)
	mux.HandleFunc("DELETE /v1/scans/{id}", h.delete)
	mux.HandleFunc("GET /v1/scans/inbox", h.inbox)
}

func (h *Handlers) userID(r *http.Request) string {
	if h.AuthVerify == nil {
		return ""
	}
	return h.AuthVerify(r)
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	uid := h.userID(r)
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required for cross-device sync")
		return
	}
	var s Scan
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(s.TargetSlug) == "" {
		writeErr(w, http.StatusBadRequest, "targetSlug required")
		return
	}
	if err := h.Repo.Create(r.Context(), uid, &s); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	uid := h.userID(r)
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	out, err := h.Repo.ListByUser(r.Context(), uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []Scan{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) update(w http.ResponseWriter, r *http.Request) {
	uid := h.userID(r)
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	var s Scan
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	s.ID = id
	if err := h.Repo.Update(r.Context(), uid, &s); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handlers) delete(w http.ResponseWriter, r *http.Request) {
	uid := h.userID(r)
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	id := r.PathValue("id")
	if err := h.Repo.Delete(r.Context(), uid, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) inbox(w http.ResponseWriter, r *http.Request) {
	uid := h.userID(r)
	if uid == "" {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	out, err := h.Repo.InboxFor(r.Context(), uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
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

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
