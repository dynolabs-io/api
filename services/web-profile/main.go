// web-profile: server-rendered public profile page at dynolabs.io/c/<slug>.
// Recipients land here when scanning a QR or following a shared link.
// Renders: name, title, photo, contact methods, Save-Contact button.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dynolabs-io/api/shared/health"
)

var version = "dev"

type Card struct {
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Company  string   `json:"company"`
	Emails   []string `json:"emails"`
	Phones   []string `json:"phones"`
	Socials  []struct {
		Kind string `json:"kind"`
		URL  string `json:"url"`
	} `json:"socials"`
	PhotoURL string `json:"photoUrl"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	apiBase := getenv("VCARD_API_URL", "http://vcard-api.dynolabs.svc")
	tmpl := template.Must(template.New("profile").Parse(profileHTML))

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("web-profile", version))
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(landingHTML))
	})

	mux.HandleFunc("GET /c/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !validSlug(slug) {
			http.Error(w, "invalid slug", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		card, err := fetchCard(ctx, apiBase, slug)
		if err != nil {
			slog.Warn("fetch card failed", "slug", slug, "err", err)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, card)
	})

	// Lead capture form submission — proxies to vcard-api /v1/leads.
	mux.HandleFunc("POST /c/{slug}/lead", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !validSlug(slug) {
			http.Error(w, "invalid slug", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		payload := map[string]string{
			"targetSlug": slug,
			"fromName":   strings.TrimSpace(r.FormValue("name")),
			"fromEmail":  strings.TrimSpace(r.FormValue("email")),
			"fromPhone":  strings.TrimSpace(r.FormValue("phone")),
			"message":    strings.TrimSpace(r.FormValue("message")),
		}
		body, _ := json.Marshal(payload)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", apiBase+"/v1/leads", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode >= 300 {
			http.Error(w, "submit failed", http.StatusBadGateway)
			return
		}
		defer res.Body.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(thanksHTML))
	})

	// Direct vCard download for "Save Contact" button. Path uses /save.vcf
	// suffix because Go 1.22 ServeMux requires wildcards to occupy a full
	// segment — `/c/{slug}.vcf` is rejected at registration time.
	mux.HandleFunc("GET /c/{slug}/save.vcf", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !validSlug(slug) {
			http.Error(w, "invalid slug", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		card, err := fetchCard(ctx, apiBase, slug)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+slug+`.vcf"`)
		_, _ = w.Write([]byte(buildVCard(card)))
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("web-profile listening", "addr", addr, "version", version, "apiBase", apiBase)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func fetchCard(ctx context.Context, apiBase, slug string) (*Card, error) {
	url := apiBase + "/v1/c/" + slug
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("upstream %d: %s", res.StatusCode, body)
	}
	var c Card
	if err := json.NewDecoder(res.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// validSlug enforces the alphabet generated by vcard-api/cards.genSlug.
// Rejects anything else to prevent SSRF-via-path or path-traversal.
func validSlug(s string) bool {
	if len(s) < 4 || len(s) > 16 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '9')) {
			return false
		}
	}
	return true
}

func buildVCard(c *Card) string {
	var sb strings.Builder
	sb.WriteString("BEGIN:VCARD\r\n")
	sb.WriteString("VERSION:3.0\r\n")
	sb.WriteString("FN:" + escapeVCard(c.Name) + "\r\n")
	if c.Title != "" {
		sb.WriteString("TITLE:" + escapeVCard(c.Title) + "\r\n")
	}
	if c.Company != "" {
		sb.WriteString("ORG:" + escapeVCard(c.Company) + "\r\n")
	}
	for _, e := range c.Emails {
		sb.WriteString("EMAIL;TYPE=INTERNET:" + escapeVCard(e) + "\r\n")
	}
	for _, p := range c.Phones {
		sb.WriteString("TEL;TYPE=CELL:" + escapeVCard(p) + "\r\n")
	}
	for _, s := range c.Socials {
		sb.WriteString("URL:" + escapeVCard(s.URL) + "\r\n")
	}
	if c.PhotoURL != "" {
		sb.WriteString("PHOTO;VALUE=uri:" + c.PhotoURL + "\r\n")
	}
	sb.WriteString("REV:" + time.Now().UTC().Format(time.RFC3339) + "\r\n")
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
}

func escapeVCard(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `;`, `\;`, "\n", `\n`, "\r", "")
	return r.Replace(s)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Dynolabs vCard</title>
  <style>
    *{box-sizing:border-box}
    html,body{margin:0;padding:0;background:#0B0B0F;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
    .wrap{max-width:560px;margin:0 auto;padding:6rem 2rem;text-align:center}
    h1{font-size:2.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 1rem}
    p{color:rgba(255,255,255,0.65);font-size:1.05rem;line-height:1.5;margin:0 0 2rem}
    .ghost{color:rgba(255,255,255,0.35);font-size:0.85rem;letter-spacing:0.08em;text-transform:uppercase}
  </style>
</head>
<body>
  <div class="wrap">
    <p class="ghost">Dynolabs</p>
    <h1>vCard</h1>
    <p>Mobile-first contact cards with QR + wallet integration. Mobile app coming soon.</p>
  </div>
</body>
</html>`

const profileHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{{ .Name }} — Dynolabs vCard</title>
  <style>
    *{box-sizing:border-box}
    html,body{margin:0;padding:0;background:#0B0B0F;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
    .wrap{max-width:480px;margin:0 auto;padding:3rem 1.5rem 5rem}
    .card{padding:2rem;border-radius:24px;background:linear-gradient(180deg,#1a1a23,#0e0e15);border:1px solid rgba(255,255,255,0.08)}
    .photo{width:96px;height:96px;border-radius:50%;background:#222;object-fit:cover;display:block;margin-bottom:1.25rem}
    h1{font-size:1.6rem;font-weight:700;letter-spacing:-0.01em;margin:0 0 0.25rem}
    .role{color:rgba(255,255,255,0.7);font-size:0.95rem;margin:0 0 1.5rem}
    .row{display:flex;align-items:center;padding:0.75rem 0;border-top:1px solid rgba(255,255,255,0.06)}
    .row:first-child{border-top:none}
    .row a{color:#fff;text-decoration:none;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .row .icon{width:32px;color:rgba(255,255,255,0.4);font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase}
    .save{display:block;margin:1.5rem 0 0;padding:1rem;border-radius:999px;background:#fff;color:#000;text-align:center;text-decoration:none;font-weight:600;font-size:1rem}
    .ghost{color:rgba(255,255,255,0.3);font-size:0.75rem;text-align:center;letter-spacing:0.08em;text-transform:uppercase;margin-top:2rem}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      {{ if .PhotoURL }}<img class="photo" src="{{ .PhotoURL }}" alt="">{{ end }}
      <h1>{{ .Name }}</h1>
      <p class="role">{{ if .Title }}{{ .Title }}{{ end }}{{ if and .Title .Company }} · {{ end }}{{ if .Company }}{{ .Company }}{{ end }}</p>
      {{ range .Emails }}<div class="row"><span class="icon">EMAIL</span><a href="mailto:{{ . }}">{{ . }}</a></div>{{ end }}
      {{ range .Phones }}<div class="row"><span class="icon">PHONE</span><a href="tel:{{ . }}">{{ . }}</a></div>{{ end }}
      {{ range .Socials }}<div class="row"><span class="icon">{{ .Kind }}</span><a href="{{ .URL }}">{{ .URL }}</a></div>{{ end }}
      <a class="save" href="/c/{{ .Slug }}/save.vcf">Save to Contacts</a>
      <details class="lead">
        <summary>Want them to call you back?</summary>
        <form method="post" action="/c/{{ .Slug }}/lead" class="leadForm">
          <input type="text" name="name" placeholder="Your name" autocomplete="name">
          <input type="email" name="email" placeholder="Your email" autocomplete="email">
          <input type="tel" name="phone" placeholder="Your phone (optional)" autocomplete="tel">
          <textarea name="message" placeholder="Quick message" rows="3"></textarea>
          <button type="submit">Send</button>
        </form>
      </details>
    </div>
    <p class="ghost">Powered by Dynolabs</p>
  </div>
</body>
</html>`

const thanksHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sent — Dynolabs vCard</title>
  <style>
    *{box-sizing:border-box}
    html,body{margin:0;padding:0;background:#0B0B0F;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
    .wrap{max-width:480px;margin:0 auto;padding:6rem 1.5rem;text-align:center}
    h1{font-size:1.6rem;font-weight:700;margin:0 0 1rem}
    p{color:rgba(255,255,255,0.7);line-height:1.5}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Sent</h1>
    <p>They'll see your details in their Dynolabs inbox.</p>
  </div>
</body>
</html>`
