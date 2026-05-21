// Package enrich — firmographic enrichment of a person's email
// address into title + company + LinkedIn URL + photo URL.
//
// Endpoint:
//
//	POST /v1/enrich/email   body {"email": "x@y.com"}
//	                        resp {"title", "company", "companyDomain",
//	                              "linkedinUrl", "photoUrl"}
//
// Why: LinkedIn's OIDC scope returns only name+email+picture. To match
// what Blinq/HiHello/Popl do (auto-fill title+company on the first
// card after LinkedIn sign-in) we call Apollo.io's People-Match API
// AFTER LinkedIn returns. This package is a thin, stdlib-only client.
//
// Provider: Apollo.io free tier (50 lookups/month).
//
//	POST https://api.apollo.io/v1/people/match
//	header X-Api-Key: <APOLLO_API_KEY>
//	body   {"email": "..."}
//
// Apollo's `person` object exposes (among many) .title,
// .organization.name, .organization.website_url, .photo_url,
// .linkedin_url. We map only those five.
//
// Graceful-skip contract: if APOLLO_API_KEY is unset the endpoint
// still returns 200 with all-empty fields. Apollo 4xx is also folded
// into empty-fields + an info log — the caller (mobile app) should
// treat enrichment as best-effort, never a blocking error.
package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// apolloEndpoint is package-level so tests can override it.
var apolloEndpoint = "https://api.apollo.io/v1/people/match"

// Result is the public response shape. Empty fields = unknown.
type Result struct {
	Title         string `json:"title"`
	Company       string `json:"company"`
	CompanyDomain string `json:"companyDomain"`
	LinkedInURL   string `json:"linkedinUrl"`
	PhotoURL      string `json:"photoUrl"`
}

// Client is a thin Apollo.io People-Match wrapper.
type Client struct {
	APIKey string
	HTTP   *http.Client
}

// NewClient returns a client. apiKey may be empty — Enrich() will
// then return an empty Result without contacting Apollo.
func NewClient(apiKey string) *Client {
	return &Client{
		APIKey: apiKey,
		HTTP:   &http.Client{Timeout: 8 * time.Second},
	}
}

// apolloReq mirrors the People-Match request body.
type apolloReq struct {
	Email string `json:"email"`
}

// apolloResp is the slice of Apollo's response we actually consume.
// Apollo returns many more fields; everything else is dropped on
// decode.
type apolloResp struct {
	Person *struct {
		Title        string `json:"title"`
		PhotoURL     string `json:"photo_url"`
		LinkedInURL  string `json:"linkedin_url"`
		Organization *struct {
			Name       string `json:"name"`
			WebsiteURL string `json:"website_url"`
		} `json:"organization"`
	} `json:"person"`
}

// Enrich calls Apollo's People-Match. On any error or missing key,
// it returns the zero Result and a nil error — enrichment is
// best-effort by design. The caller never needs to branch on err.
func (c *Client) Enrich(ctx context.Context, email string) (Result, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return Result{}, errors.New("email required")
	}
	if c == nil || c.APIKey == "" {
		slog.Info("enrich skipped: APOLLO_API_KEY not set", "email_domain", domainOf(email))
		return Result{}, nil
	}

	body, _ := json.Marshal(apolloReq{Email: email})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apolloEndpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("enrich: build request failed", "err", err)
		return Result{}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Api-Key", c.APIKey)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		slog.Warn("enrich: apollo request failed", "err", err)
		return Result{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// 401/402/403/429 etc — treat as empty-fields. Log enough
		// to debug, never enough to leak the key.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		slog.Info("enrich: apollo non-2xx, returning empty fields",
			"status", resp.StatusCode,
			"email_domain", domainOf(email),
			"body_snippet", string(snippet))
		return Result{}, nil
	}

	var ar apolloResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		slog.Warn("enrich: apollo decode failed", "err", err)
		return Result{}, nil
	}
	out := Result{}
	if ar.Person != nil {
		out.Title = ar.Person.Title
		out.LinkedInURL = ar.Person.LinkedInURL
		out.PhotoURL = ar.Person.PhotoURL
		if ar.Person.Organization != nil {
			out.Company = ar.Person.Organization.Name
			out.CompanyDomain = hostOf(ar.Person.Organization.WebsiteURL)
		}
	}
	slog.Info("enrich ok",
		"email_domain", domainOf(email),
		"has_title", out.Title != "",
		"has_company", out.Company != "",
		"has_linkedin", out.LinkedInURL != "")
	return out, nil
}

// Handlers wires the email + LinkedIn enrichment endpoints into the
// http.ServeMux. Either field may be a no-op client (empty config) —
// the endpoints still respond 200 with zero Result.
type Handlers struct {
	Client     *Client
	LinkedIn   *LinkedInClient
	AuthVerify func(r *http.Request) string // returns "" if unauthenticated
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/enrich/email", h.enrichEmail)
	mux.HandleFunc("POST /v1/enrich/linkedin", h.enrichLinkedIn)
}

type enrichReq struct {
	Email string `json:"email"`
}

type enrichLinkedInReq struct {
	Vanity string `json:"vanity"`
}

func (h *Handlers) enrichEmail(w http.ResponseWriter, r *http.Request) {
	// Auth required — enrichment burns a finite Apollo quota; we
	// don't want anonymous callers grinding it down.
	if h.AuthVerify != nil && h.AuthVerify(r) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth required"})
		return
	}
	var req enrichReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	out, _ := h.Client.Enrich(r.Context(), req.Email)
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) enrichLinkedIn(w http.ResponseWriter, r *http.Request) {
	if h.AuthVerify != nil && h.AuthVerify(r) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "auth required"})
		return
	}
	var req enrichLinkedInReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if strings.TrimSpace(req.Vanity) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vanity required"})
		return
	}
	out, _ := h.LinkedIn.EnrichByVanity(r.Context(), req.Vanity)
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// domainOf returns the bit after '@', or "" on a malformed address.
// Used in logs to avoid leaking the local-part.
func domainOf(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 || i == len(email)-1 {
		return ""
	}
	return email[i+1:]
}

// hostOf strips scheme + path from a URL, returning just the host.
// "" on parse failure; the caller falls back to empty.
func hostOf(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// Cheap manual parse — avoids the net/url cost and is robust to
	// the half-formed strings Apollo occasionally returns
	// ("example.com" without scheme).
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "www.")
	return s
}
