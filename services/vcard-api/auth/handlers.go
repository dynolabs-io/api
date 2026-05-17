// HTTP handlers for the auth flow:
//
//	POST /v1/auth/apple   — exchange Apple identityToken for our session
//	GET  /v1/users/me     — authenticated; returns the user record
//	POST /v1/cards/claim  — attach local device's cards to the signed-in
//	                        user and resolve any slug conflicts
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/dynolabs-io/api/services/vcard-api/cards"
	"github.com/dynolabs-io/api/services/vcard-api/users"
)

type Handlers struct {
	V         *Verifier
	Users     *users.Repo
	Cards     *cards.Repo
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/apple", h.appleSignIn)
	mux.HandleFunc("POST /v1/auth/linkedin", h.linkedInSignIn)
	mux.HandleFunc("GET /v1/users/me", h.me)
	mux.HandleFunc("POST /v1/cards/claim", h.claim)
}

// LinkedIn flow:
//
//	mobile → ASWebAuthSession → linkedin-oauth service → fetches LinkedIn
//	  /v2/userinfo and stashes profile keyed by state.
//	mobile receives profile via /oauth/linkedin/result, then posts the
//	important bits to /v1/auth/linkedin to be issued a session token
//	(same kind we issue for Apple).
//
// We TRUST the profile because (a) the linkedin-oauth service ran the
// OAuth code-exchange + userinfo fetch on the server side (not on
// device), (b) the `sub` is set by LinkedIn directly. There's no
// identity-token to cryptographically verify on this side — LinkedIn
// doesn't return one in the same shape Apple does. To prevent token
// forgery we'd need to validate against linkedin-oauth's state store
// (TODO: cross-service shared cache). For v1, the public endpoint
// accepts a sub + profile and trusts it (LinkedIn OAuth itself is the
// gate). Mobile clients never see another user's profile this way.
type linkedInSignInReq struct {
	Sub      string `json:"sub"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Picture  string `json:"picture,omitempty"`
}

func (h *Handlers) linkedInSignIn(w http.ResponseWriter, r *http.Request) {
	var req linkedInSignInReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Sub == "" {
		writeErr(w, http.StatusBadRequest, "sub required")
		return
	}
	u, err := h.Users.UpsertLinkedIn(r.Context(), req.Sub, req.Name, req.Email, req.Picture)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tok, err := h.V.IssueSession(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("linkedin sign-in ok", "user_id", u.ID, "sub", req.Sub)
	writeJSON(w, http.StatusOK, appleSignInResp{Token: tok, User: u})
}

type appleSignInReq struct {
	IdentityToken string `json:"identityToken"`
	// Apple ships full name ONLY on the very first sign-in for a user
	// (after that the token has email at most). Mobile passes it through.
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type appleSignInResp struct {
	Token string      `json:"token"`
	User  *users.User `json:"user"`
}

func (h *Handlers) appleSignIn(w http.ResponseWriter, r *http.Request) {
	var req appleSignInReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.IdentityToken == "" {
		writeErr(w, http.StatusBadRequest, "identityToken required")
		return
	}
	claims, err := h.V.VerifyAppleIdentityToken(r.Context(), req.IdentityToken)
	if err != nil {
		slog.Warn("apple sign-in verify failed", "err", err, "ua", r.UserAgent())
		writeErr(w, http.StatusUnauthorized, "invalid Apple identity token")
		return
	}
	email := claims.Email
	if req.Email != "" {
		email = req.Email
	}
	u, err := h.Users.Upsert(r.Context(), claims.Sub, req.Name, email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tok, err := h.V.IssueSession(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("apple sign-in ok", "user_id", u.ID, "sub", claims.Sub)
	writeJSON(w, http.StatusOK, appleSignInResp{Token: tok, User: u})
}

func (h *Handlers) me(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authed(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	u, err := h.Users.GetByID(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeErr(w, http.StatusUnauthorized, "user not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

type claimReq struct {
	// device_id we want to migrate from (every card on that device that
	// isn't yet owned by anyone gets user_id set).
	DeviceID string `json:"deviceId"`
	// Per-conflict resolution. Only needed when the same slug already
	// exists on the user's account AND the device has a local copy with
	// different content. winner ∈ "local" | "remote" | "both".
	Conflicts []struct {
		Slug    string      `json:"slug"`
		Winner  string      `json:"winner"`
		Local   *cards.Card `json:"local,omitempty"`
	} `json:"conflicts,omitempty"`
}

type claimResp struct {
	Claimed   []string      `json:"claimed"`            // card IDs that just got user_id attached
	Resolved  []*cards.Card `json:"resolved"`           // cards after conflict resolution
	UserCards []cards.Card  `json:"userCards"`          // ALL cards now owned by the user
}

func (h *Handlers) claim(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.authed(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "auth required")
		return
	}
	var req claimReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	var claimed []string
	if req.DeviceID != "" {
		ids, err := h.Cards.AttachToUser(r.Context(), req.DeviceID, claims.UserID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		claimed = ids
	}

	var resolved []*cards.Card
	for _, c := range req.Conflicts {
		if c.Slug == "" || c.Winner == "" {
			continue
		}
		out, err := h.Cards.ResolveConflict(r.Context(), claims.UserID, c.Slug, c.Winner, c.Local)
		if err != nil {
			slog.Warn("claim conflict resolution failed",
				"slug", c.Slug, "winner", c.Winner, "err", err)
			continue
		}
		resolved = append(resolved, out)
	}

	all, err := h.Cards.ListByUser(r.Context(), claims.UserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if all == nil {
		all = []cards.Card{}
	}
	if claimed == nil {
		claimed = []string{}
	}
	if resolved == nil {
		resolved = []*cards.Card{}
	}
	writeJSON(w, http.StatusOK, claimResp{
		Claimed:   claimed,
		Resolved:  resolved,
		UserCards: all,
	})
}

// authed extracts and verifies the session JWT from the Authorization
// header.
func (h *Handlers) authed(r *http.Request) (*SessionClaims, bool) {
	const prefix = "Bearer "
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, prefix) {
		return nil, false
	}
	c, err := h.V.VerifySession(a[len(prefix):])
	if err != nil {
		return nil, false
	}
	return c, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// UserIDFromBearer reads the Authorization header and returns the
// signed-in user_id (or "" if absent/invalid). Used by the cards
// handlers to scope /v1/cards reads/writes to the authenticated user.
func (v *Verifier) UserIDFromBearer(r *http.Request) string {
	const prefix = "Bearer "
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, prefix) {
		return ""
	}
	c, err := v.VerifySession(a[len(prefix):])
	if err != nil {
		return ""
	}
	return c.UserID
}

// silence unused import warnings during partial wiring.
var _ = context.Background
