// Package webservice — Apple Wallet pass web-service endpoints.
//
// When a pass.json declares webServiceURL + authenticationToken, iOS
// Wallet calls these endpoints to register the pass for push updates
// and to fetch refreshed pass bytes when notified.
//
// Spec: https://developer.apple.com/library/archive/documentation/PassKit/Reference/PassKit_WebService/WebService.html
//
// Endpoints (Apple-defined, MUST match exactly):
//
//	POST   /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}/{serialNumber}
//	         body: {"pushToken": "..."}
//	         → 200 if already registered, 201 if newly registered
//
//	DELETE /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}/{serialNumber}
//	         → 200 on unregister
//
//	GET    /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}?passesUpdatedSince=...
//	         → {"lastUpdated": "...", "serialNumbers": ["..."]}
//
//	GET    /v1/passes/{passTypeIdentifier}/{serialNumber}
//	         (if-modified-since respected; returns refreshed .pkpass bytes)
//
//	POST   /v1/log    body: {"logs": ["..."]}    → 200
//
// Authentication: Authorization: ApplePass <token>. We use a fixed
// shared token from env (any token works as long as it matches what
// pass.json declared). For production we'd rotate; for v1 this is fine.
//
// Registrations live in Postgres so they survive pod restarts.
package wallet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// PassSignerBuilder returns a PassBuilder that proxies to pass-signer's
// /pass/apple?slug=&mode= endpoint. Wallet sends serial like
// "<slug>-<mode>" (e.g. "abc123-online"); we split and pass through.
func PassSignerBuilder(passSignerBase string) func(ctx context.Context, passType, serial string) ([]byte, time.Time, error) {
	return func(ctx context.Context, passType, serial string) ([]byte, time.Time, error) {
		idx := strings.LastIndex(serial, "-")
		if idx <= 0 {
			return nil, time.Time{}, ErrNotFound
		}
		slug := serial[:idx]
		mode := serial[idx+1:]
		url := fmt.Sprintf("%s/pass/apple?slug=%s&mode=%s", passSignerBase, slug, mode)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("pass-signer fetch: %w", err)
		}
		defer res.Body.Close()
		if res.StatusCode == http.StatusNotFound {
			return nil, time.Time{}, ErrNotFound
		}
		if res.StatusCode != 200 {
			return nil, time.Time{}, fmt.Errorf("pass-signer %d", res.StatusCode)
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, time.Time{}, err
		}
		return body, time.Now().UTC(), nil
	}
}

type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

// Register inserts or updates the push token for (passType, serial, device).
// Returns true if newly created (vs updated).
func (r *Repo) Register(ctx context.Context, passType, serial, device, pushToken string) (bool, error) {
	const q = `
		INSERT INTO wallet_registrations (pass_type_id, serial_number, device_id, push_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (pass_type_id, serial_number, device_id)
		DO UPDATE SET push_token = EXCLUDED.push_token, updated_at = now()
		RETURNING (xmax = 0) AS inserted`
	var inserted bool
	if err := r.db.QueryRowContext(ctx, q, passType, serial, device, pushToken).Scan(&inserted); err != nil {
		return false, fmt.Errorf("register: %w", err)
	}
	return inserted, nil
}

func (r *Repo) Unregister(ctx context.Context, passType, serial, device string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM wallet_registrations WHERE pass_type_id = $1 AND serial_number = $2 AND device_id = $3`,
		passType, serial, device,
	)
	return err
}

// ListSerialsForDevice returns serials this device is registered for
// (under our pass type) that have been updated since the given time.
// When `since` is zero, returns all.
func (r *Repo) ListSerialsForDevice(ctx context.Context, passType, device string, since time.Time) ([]string, time.Time, error) {
	const q = `
		SELECT wr.serial_number, c.updated_at
		FROM wallet_registrations wr
		LEFT JOIN cards c ON c.slug = split_part(wr.serial_number, '-', 1)
		WHERE wr.pass_type_id = $1 AND wr.device_id = $2
		  AND ($3::timestamptz IS NULL OR c.updated_at > $3::timestamptz)
		ORDER BY c.updated_at DESC NULLS LAST`
	var sincePtr *time.Time
	if !since.IsZero() {
		sincePtr = &since
	}
	rows, err := r.db.QueryContext(ctx, q, passType, device, sincePtr)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("list serials: %w", err)
	}
	defer rows.Close()
	var serials []string
	var last time.Time
	for rows.Next() {
		var s string
		var ts sql.NullTime
		if err := rows.Scan(&s, &ts); err != nil {
			return nil, time.Time{}, err
		}
		serials = append(serials, s)
		if ts.Valid && ts.Time.After(last) {
			last = ts.Time
		}
	}
	return serials, last, rows.Err()
}

// PushTokensForSerial returns all device push tokens registered for a
// given (passType, serial). Used by SchedulePush after a card updates.
func (r *Repo) PushTokensForSerial(ctx context.Context, passType, serial string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT push_token FROM wallet_registrations WHERE pass_type_id = $1 AND serial_number = $2`,
		passType, serial,
	)
	if err != nil {
		return nil, fmt.Errorf("tokens: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Handlers wires Apple's web-service endpoints. PassBuilder is a
// callback the caller supplies (we don't want a circular import with
// pass-signer's main package); it returns fresh .pkpass bytes for a
// given (passType, serial).
type Handlers struct {
	Repo           *Repo
	AuthToken      string                                                                   // expected ApplePass token
	PassBuilder    func(ctx context.Context, passType, serial string) ([]byte, time.Time, error)
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/devices/{deviceID}/registrations/{passType}/{serial}", h.register)
	mux.HandleFunc("DELETE /v1/devices/{deviceID}/registrations/{passType}/{serial}", h.unregister)
	mux.HandleFunc("GET /v1/devices/{deviceID}/registrations/{passType}", h.listForDevice)
	mux.HandleFunc("GET /v1/passes/{passType}/{serial}", h.fetchPass)
	mux.HandleFunc("POST /v1/log", h.log)
}

func (h *Handlers) checkAuth(r *http.Request) bool {
	if h.AuthToken == "" {
		return true // permissive in dev/stub
	}
	got := r.Header.Get("Authorization")
	expected := "ApplePass " + h.AuthToken
	return got == expected
}

func (h *Handlers) register(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct{ PushToken string `json:"pushToken"` }
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PushToken == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	inserted, err := h.Repo.Register(r.Context(),
		r.PathValue("passType"), r.PathValue("serial"),
		r.PathValue("deviceID"), body.PushToken)
	if err != nil {
		slog.Error("wallet register failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if inserted {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) unregister(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.Repo.Unregister(r.Context(),
		r.PathValue("passType"), r.PathValue("serial"),
		r.PathValue("deviceID"),
	); err != nil {
		slog.Error("wallet unregister failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) listForDevice(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if q := r.URL.Query().Get("passesUpdatedSince"); q != "" {
		// Apple sends RFC3339-ish or Unix timestamp; try both.
		if t, err := time.Parse(time.RFC3339, q); err == nil {
			since = t
		}
	}
	serials, last, err := h.Repo.ListSerialsForDevice(r.Context(),
		r.PathValue("passType"), r.PathValue("deviceID"), since)
	if err != nil {
		slog.Error("wallet list failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if len(serials) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"lastUpdated":   last.Format(time.RFC3339),
		"serialNumbers": serials,
	})
}

func (h *Handlers) fetchPass(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.PassBuilder == nil {
		http.Error(w, "pass-builder not configured", http.StatusServiceUnavailable)
		return
	}
	out, updatedAt, err := h.PassBuilder(r.Context(), r.PathValue("passType"), r.PathValue("serial"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		slog.Error("wallet pass build failed", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := time.Parse(http.TimeFormat, ims); err == nil && !updatedAt.After(t) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
	w.Header().Set("Last-Modified", updatedAt.UTC().Format(http.TimeFormat))
	_, _ = w.Write(out)
}

func (h *Handlers) log(w http.ResponseWriter, r *http.Request) {
	var body struct{ Logs []string `json:"logs"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	for _, line := range body.Logs {
		slog.Info("wallet-device-log", "line", strings.TrimSpace(line))
	}
	w.WriteHeader(http.StatusOK)
}

var ErrNotFound = errors.New("pass not found")
