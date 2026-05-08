// Package health exposes a tiny HTTP handler each service mounts at /healthz.
// Per CAP-AP design these endpoints stay liveness-only — they MUST NOT depend
// on downstream services (DB, NATS, S3) so a partition doesn't take a pod
// out of rotation. Readiness is a separate concern handled per-service.
package health

import (
	"encoding/json"
	"net/http"
	"time"
)

type Response struct {
	Status  string    `json:"status"`
	Service string    `json:"service"`
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
}

// Handler returns an http.Handler that responds 200 with service identity.
// Pass the service name (e.g. "vcard-api") and the build SHA injected at
// link time via -ldflags.
func Handler(service, version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := Response{
			Status:  "ok",
			Service: service,
			Version: version,
			Time:    time.Now().UTC(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}
