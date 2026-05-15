package cards

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

type Handlers struct {
	Repo *Repo
	// AuthVerify returns the authenticated user_id from the Authorization
	// header (or "" if missing/invalid). Set by main from the auth
	// Verifier. Optional — if nil, all calls are treated as anonymous
	// device-bound (legacy behavior).
	AuthVerify func(r *http.Request) string
}

func (h *Handlers) userID(r *http.Request) string {
	if h.AuthVerify == nil {
		return ""
	}
	return h.AuthVerify(r)
}

func (h *Handlers) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/cards", h.create)
	mux.HandleFunc("GET /v1/cards", h.list)
	mux.HandleFunc("GET /v1/cards/{id}", h.get)
	mux.HandleFunc("PATCH /v1/cards/{id}", h.update)
	mux.HandleFunc("DELETE /v1/cards/{id}", h.delete)
	// Public — recipients hitting the web-profile use this via web-profile's
	// in-cluster fetch. Also useful for the direct integration tests.
	mux.HandleFunc("GET /v1/c/{slug}", h.publicBySlug)
	// Mobile crash log sink — writes to slog so we can read in `kubectl logs`.
	mux.HandleFunc("POST /v1/crash", h.crash)
}

func (h *Handlers) crash(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	slog.Error("mobile-crash", "body", string(body), "ua", r.UserAgent())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	var c Card
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if c.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if err := h.Repo.Create(r.Context(), &c); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// If the caller is signed in, attach the user_id so this card syncs
	// across the user's other devices. Anonymous cards stay device-bound.
	if uid := h.userID(r); uid != "" {
		if err := h.Repo.SetUser(r.Context(), c.ID, uid); err == nil {
			c.UserID = uid
		}
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	// Signed-in path: union of the user's cards + any device cards on
	// THIS device that don't yet have a user_id (lets us show
	// not-yet-claimed local cards alongside synced ones until the
	// caller hits the claim endpoint).
	if uid := h.userID(r); uid != "" {
		out, err := h.Repo.ListByUser(r.Context(), uid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		deviceID := r.URL.Query().Get("device_id")
		if deviceID != "" {
			dev, err := h.Repo.ListByDevice(r.Context(), deviceID)
			if err == nil {
				seen := make(map[string]bool, len(out))
				for _, c := range out {
					seen[c.ID] = true
				}
				for _, c := range dev {
					if !seen[c.ID] && c.UserID == "" {
						out = append(out, c)
					}
				}
			}
		}
		if out == nil {
			out = []Card{}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	// Anonymous path: device-bound.
	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		writeErr(w, http.StatusBadRequest, "device_id required")
		return
	}
	cards, err := h.Repo.ListByDevice(r.Context(), deviceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cards == nil {
		cards = []Card{}
	}
	writeJSON(w, http.StatusOK, cards)
}

func (h *Handlers) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.Repo.GetByID(r.Context(), id)
	if err != nil {
		respondNotFoundOr500(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Handlers) publicBySlug(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	c, err := h.Repo.GetBySlug(r.Context(), slug)
	if err != nil {
		respondNotFoundOr500(w, err)
		return
	}
	// Strip device_id from the public projection.
	c.DeviceID = ""
	writeJSON(w, http.StatusOK, c)
}

func (h *Handlers) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var c Card
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	c.ID = id
	if err := h.Repo.Update(r.Context(), &c); err != nil {
		respondNotFoundOr500(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Handlers) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Repo.Delete(r.Context(), id); err != nil {
		respondNotFoundOr500(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func respondNotFoundOr500(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
