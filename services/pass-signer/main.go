// pass-signer: signs Apple .pkpass + Google Wallet JWT.
//
// Apple flow:
//   POST /pass/apple {"cardId":"<uuid>"} → fetches card from vcard-api,
//   builds pass.json (vCard QR + name + title + company + email/phone in
//   back fields), signs with Pass Type ID cert + WWDR intermediate, returns
//   binary .pkpass with Content-Type application/vnd.apple.pkpass.
//
// Stub flag PASS_SIGNER_STUB=1 keeps Apple endpoint disabled when cert
// secret isn't mounted (defensive — secret presence is the real check).

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif" // register GIF decoder for image.Decode
	"image/jpeg"  // encoder for the embedded vCard PHOTO thumbnail
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dynolabs-io/api/services/pass-signer/pkpass"
	"github.com/dynolabs-io/api/shared/health"
	qrcode "github.com/skip2/go-qrcode"
)

// renderQRPNG produces a QR code PNG sized to fill the canvas as much
// as possible. The QR is square; for non-square canvases it's centered
// at full min(w,h) with white margin in the longer dimension.
// No inner padding — the QR goes edge-to-edge in its dimension.
func renderQRPNG(content string, w, h int) ([]byte, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	q.DisableBorder = true
	// QR is square; fill the smaller canvas dimension entirely.
	qrSize := h
	if w < h {
		qrSize = w
	}
	qrPNG, err := q.PNG(qrSize)
	if err != nil {
		return nil, err
	}
	qrImg, _, err := image.Decode(bytes.NewReader(qrPNG))
	if err != nil {
		return nil, err
	}
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			canvas.SetNRGBA(x, y, color.NRGBA{255, 255, 255, 255})
		}
	}
	ox := (w - qrImg.Bounds().Dx()) / 2
	oy := (h - qrImg.Bounds().Dy()) / 2
	bounds := qrImg.Bounds()
	for y := 0; y < bounds.Dy(); y++ {
		for x := 0; x < bounds.Dx(); x++ {
			r, g, b, a := qrImg.At(x, y).RGBA()
			canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var version = "dev"

type cardSocial struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}
type card struct {
	ID           string       `json:"id"`
	Slug         string       `json:"slug"`
	Label        string       `json:"label"`
	Name         string       `json:"name"`
	Title        string       `json:"title"`
	Company      string       `json:"company"`
	Emails       []string     `json:"emails"`
	Phones       []string     `json:"phones"`
	Socials      []cardSocial `json:"socials"`
	PhotoURL     string       `json:"photoUrl"`
	BrandLogoURL string       `json:"brandLogoUrl"`
	Template     string       `json:"template"`
	CustomColor  string       `json:"customColor"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	stub := os.Getenv("PASS_SIGNER_STUB") == "1"
	apiBase := getenv("VCARD_API_URL", "http://vcard-api.dynolabs.svc")
	passTypeID := getenv("APPLE_PASS_TYPE_ID", "pass.io.dynolabs.vcard")
	teamID := getenv("APPLE_TEAM_ID", "77GHJHUGD4")
	webBase := getenv("WEB_BASE", "https://dynolabs.io")
	certPath := getenv("APPLE_PASS_CERT_PATH", "/etc/dynolabs-apple-pass/passcert.pem")
	keyPath := getenv("APPLE_PASS_KEY_PATH", "/etc/dynolabs-apple-pass/passkey.pem")
	wwdrPath := getenv("APPLE_PASS_WWDR_PATH", "/etc/dynolabs-apple-pass/wwdr.pem")

	var (
		signer *pkpass.Signer
		signMu sync.RWMutex
	)
	if !stub {
		certPEM, err1 := os.ReadFile(certPath)
		keyPEM, err2 := os.ReadFile(keyPath)
		wwdrPEM, err3 := os.ReadFile(wwdrPath)
		if err1 == nil && err2 == nil && err3 == nil {
			s, err := pkpass.LoadSigner(certPEM, keyPEM, wwdrPEM)
			if err != nil {
				slog.Error("load signer failed", "err", err)
				os.Exit(1)
			}
			signer = s
			slog.Info("pass-signer loaded",
				"subject", signer.PassCert.Subject.CommonName,
				"wwdr", signer.WWDR.Subject.CommonName)
		} else {
			slog.Warn("pass cert files missing — falling back to stub mode",
				"cert_err", err1, "key_err", err2, "wwdr_err", err3)
			stub = true
		}
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler("pass-signer", version))
	mux.Handle("GET /pass/healthz", health.Handler("pass-signer", version))
	readyz := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"ready":true,"stub":%t}`, stub)
	}
	mux.HandleFunc("GET /readyz", readyz)
	mux.HandleFunc("GET /pass/readyz", readyz)

	// Both GET (?slug=) and POST (JSON body) are supported. GET is the
	// simplest mobile-side path: app calls Linking.openURL with the URL
	// and iOS handles the rest.
	applePass := func(w http.ResponseWriter, r *http.Request) {
		if stub {
			http.Error(w, `{"error":"stub-mode: Apple Pass Type ID cert not yet provisioned"}`, http.StatusServiceUnavailable)
			return
		}
		var cardID, slug string
		if r.Method == http.MethodGet {
			cardID = r.URL.Query().Get("cardId")
			slug = r.URL.Query().Get("slug")
		} else {
			var body struct {
				CardID string `json:"cardId"`
				Slug   string `json:"slug"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}
			cardID, slug = body.CardID, body.Slug
		}
		if cardID == "" && slug == "" {
			http.Error(w, `{"error":"cardId or slug required"}`, http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		c, err := fetchCard(ctx, apiBase, cardID, slug)
		if err != nil {
			slog.Warn("fetch card failed", "err", err, "slug", slug, "cardId", cardID, "ua", r.UserAgent())
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusBadGateway)
			return
		}
		slog.Info("pass requested",
			"slug-requested", slug, "cardId-requested", cardID,
			"name-served", c.Name, "slug-served", c.Slug,
			"hasPhoto", c.PhotoURL != "",
			"hasLogo", c.BrandLogoURL != "",
			"ua", r.UserAgent())

		// Fetch brand logo + profile photo BEFORE buildPass so the QR
		// vCard can embed a small JPEG thumbnail of the photo (iOS Camera
		// only saves embedded photos from a scanned QR, not remote URIs).
		var brandLogoBytes, photoBytes []byte
		if c.BrandLogoURL != "" && strings.HasPrefix(c.BrandLogoURL, "http") {
			if b, err := fetchThumbnail(r.Context(), c.BrandLogoURL); err == nil && len(b) > 0 {
				brandLogoBytes = b
			} else if err != nil {
				slog.Warn("brand logo fetch failed", "err", err, "url", c.BrandLogoURL)
			}
		}
		if c.PhotoURL != "" && strings.HasPrefix(c.PhotoURL, "http") {
			if p, err := fetchThumbnail(r.Context(), c.PhotoURL); err == nil && len(p) > 0 {
				photoBytes = p
			} else if err != nil {
				slog.Warn("photo fetch failed", "err", err, "url", c.PhotoURL)
			}
		}

		// Build the small embedded photo for the vCard QR (≤ ~2 KB).
		var embeddedPhotoBytes []byte
		if len(photoBytes) > 0 {
			if thumb, err := thumbnailJPEG(photoBytes, 80, 35); err == nil {
				embeddedPhotoBytes = thumb
			} else {
				slog.Warn("vcard photo thumb encode failed", "err", err)
			}
		}

		pass := buildPass(c, passTypeID, teamID, webBase, embeddedPhotoBytes)

		// Apple's "logo" header slot (top-left, beside logoText) is a
		// small decorative chip. We keep it as a brand-colored tile so the
		// company logo doesn't get squished into 160×50 — it gets the full
		// strip width below. icon is also brand-colored for the lock-screen
		// notification.
		iconAsset := iconPNG(87, c.Template, c.CustomColor)
		logoAsset := iconPNG(160, c.Template, c.CustomColor)
		assets := map[string][]byte{
			"icon.png":    iconAsset,
			"icon@2x.png": iconAsset,
			"icon@3x.png": iconAsset,
			"logo.png":    logoAsset,
			"logo@2x.png": logoAsset,
		}

		// The strip is the ONE composite image. It always packs both the
		// face photo AND the company logo on a brand-color background so
		// every pass uses the full canvas — no more empty space, no more
		// either/or.
		if s, err := renderHeroStrip(c, photoBytes, brandLogoBytes, 1125, 432); err == nil {
			assets["strip.png"] = s
			assets["strip@2x.png"] = s
		}

		signMu.RLock()
		defer signMu.RUnlock()
		out, err := signer.Build(pass, assets)
		if err != nil {
			slog.Error("build pass failed", "err", err)
			http.Error(w, `{"error":"sign failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.apple.pkpass")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pkpass"`, c.Slug))
		_, _ = w.Write(out)
	}
	mux.HandleFunc("GET /pass/apple", applePass)
	mux.HandleFunc("POST /pass/apple", applePass)

	mux.HandleFunc("POST /pass/google", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"stub-mode: Google Wallet issuer not yet provisioned"}`, http.StatusServiceUnavailable)
	})

	addr := getenv("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("pass-signer listening", "addr", addr, "version", version, "stub", stub, "passTypeID", passTypeID)
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

// fitToCanvas resizes/crops src image bytes to fit exactly w×h pixels,
// preserving aspect with a center-cover crop. Returns PNG bytes.
func fitToCanvas(src []byte, w, h int) ([]byte, error) {
	srcImg, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	sw, sh := srcImg.Bounds().Dx(), srcImg.Bounds().Dy()
	// Cover crop: scale so the smaller ratio fills, then center-crop.
	srcRatio := float64(sw) / float64(sh)
	dstRatio := float64(w) / float64(h)
	var cropW, cropH int
	if srcRatio > dstRatio {
		// src wider — crop sides
		cropH = sh
		cropW = int(float64(sh) * dstRatio)
	} else {
		// src taller — crop top/bottom
		cropW = sw
		cropH = int(float64(sw) / dstRatio)
	}
	cropX := (sw - cropW) / 2
	cropY := (sh - cropH) / 2
	// Nearest-neighbor scale; quality fine for a wallet thumbnail.
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		sy := cropY + (y*cropH)/h
		for x := 0; x < w; x++ {
			sx := cropX + (x*cropW)/w
			r, g, b, a := srcImg.At(sx, sy).RGBA()
			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// brandColorHex returns the brand color for a card. customColor wins,
// otherwise the template provides a default.
func brandColorHex(c *card) string {
	if c.CustomColor != "" {
		return c.CustomColor
	}
	switch c.Template {
	case "gradient":
		return "#1F2533"
	case "glass":
		return "#101012"
	case "custom":
		return "#0A66C2"
	}
	return "#0B0B0F"
}

// renderHeroStrip composes the front banner of the Wallet pass. The strip
// is 1125×432 (the largest Apple slot for eventTicket) and ALWAYS uses the
// full canvas — no empty space.
//
// Layout adapts to whatever the user uploaded:
//
//   photo + logo → photo as a left-anchored circle, logo on the right half
//                  centered on the brand color band. Both visible at once.
//   photo only   → photo cover-cropped to the full strip + brand-color
//                  vignette on the right edge (keeps face anchored left).
//   logo only    → logo centered on full brand-color background, sized to
//                  ~70% of canvas height.
//   neither      → solid brand color (lets the Apple-rendered text fields
//                  fill what would otherwise be a void).
func renderHeroStrip(c *card, photoBytes, logoBytes []byte, w, h int) ([]byte, error) {
	br, bg, bb := hexToRGB(brandColorHex(c))
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			canvas.SetNRGBA(x, y, color.NRGBA{R: br, G: bg, B: bb, A: 255})
		}
	}

	hasPhoto := len(photoBytes) > 0
	hasLogo := len(logoBytes) > 0

	switch {
	case hasPhoto && hasLogo:
		// SPLIT LAYOUT — photo circle anchored left, logo right.
		// Photo circle ~ 360px diameter, vertically centered, 36px from left.
		photoDiam := h * 90 / 100 // 388
		if photoDiam > w*38/100 {
			photoDiam = w * 38 / 100
		}
		photoOX := h * 5 / 100 // 21px left margin
		photoOY := (h - photoDiam) / 2
		drawCircularPhoto(canvas, photoBytes, photoOX, photoOY, photoDiam)
		// Logo in the right ~58% of canvas (from photo right edge to right).
		logoBoxX := photoOX + photoDiam + h*8/100
		logoBoxW := w - logoBoxX - h*5/100
		logoBoxH := h * 80 / 100
		logoBoxY := (h - logoBoxH) / 2
		drawLogoFit(canvas, logoBytes, logoBoxX, logoBoxY, logoBoxW, logoBoxH)
	case hasPhoto:
		// PHOTO-DOMINANT — cover-crop fit. Apple's pass already has a brand
		// color background, so we let the photo own the strip.
		coverDrawPhoto(canvas, photoBytes, 0, 0, w, h)
	case hasLogo:
		// LOGO-CENTERED — fits ~70% of canvas height, max 80% width.
		boxH := h * 70 / 100
		boxW := w * 80 / 100
		drawLogoFit(canvas, logoBytes, (w-boxW)/2, (h-boxH)/2, boxW, boxH)
	default:
		// Plain brand color — Apple's text overlay handles content.
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawCircularPhoto draws a center-cover-cropped photo inside a circle at
// (ox, oy) with the given diameter. Pixels outside the circle are left
// untouched so the underlying brand color shows through.
func drawCircularPhoto(canvas *image.NRGBA, photoBytes []byte, ox, oy, diam int) {
	photoImg, _, err := image.Decode(bytes.NewReader(photoBytes))
	if err != nil {
		return
	}
	sw, sh := photoImg.Bounds().Dx(), photoImg.Bounds().Dy()
	sz := sw
	if sh < sw {
		sz = sh
	}
	sx0 := (sw - sz) / 2
	sy0 := (sh - sz) / 2
	radius := diam / 2
	cx := ox + radius
	cy := oy + radius
	r2 := radius * radius
	// Draw a thin white ring (4px) just inside the radius to make the photo
	// pop against the brand color.
	ringInner := radius - 4
	ringInner2 := ringInner * ringInner
	for y := 0; y < diam; y++ {
		for x := 0; x < diam; x++ {
			dx := (ox + x) - cx
			dy := (oy + y) - cy
			d2 := dx*dx + dy*dy
			if d2 > r2 {
				continue
			}
			if d2 >= ringInner2 {
				canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
				continue
			}
			sx := sx0 + (x*sz)/diam
			sy := sy0 + (y*sz)/diam
			r, g, b, a := photoImg.At(sx, sy).RGBA()
			canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
}

// drawLogoFit fits the logo bytes inside (ox, oy, w, h) preserving aspect.
// Transparent pixels (a < 16) are skipped so the brand color underneath
// shows through — required for typical PNG logos.
func drawLogoFit(canvas *image.NRGBA, logoBytes []byte, ox, oy, w, h int) {
	logoImg, _, err := image.Decode(bytes.NewReader(logoBytes))
	if err != nil {
		return
	}
	lw, lh := logoImg.Bounds().Dx(), logoImg.Bounds().Dy()
	if lw == 0 || lh == 0 {
		return
	}
	srcRatio := float64(lw) / float64(lh)
	dstRatio := float64(w) / float64(h)
	var contentW, contentH int
	if srcRatio > dstRatio {
		contentW = w
		contentH = int(float64(w) / srcRatio)
	} else {
		contentH = h
		contentW = int(float64(h) * srcRatio)
	}
	px := ox + (w-contentW)/2
	py := oy + (h-contentH)/2
	for y := 0; y < contentH; y++ {
		sy := (y * lh) / contentH
		for x := 0; x < contentW; x++ {
			sx := (x * lw) / contentW
			r, g, b, a := logoImg.At(sx, sy).RGBA()
			if a>>8 < 16 {
				continue
			}
			canvas.SetNRGBA(px+x, py+y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
}

// coverDrawPhoto blits a center-cover-cropped photo onto canvas at (ox, oy,
// w, h). The photo fills the rectangle exactly, cropping the longer axis.
func coverDrawPhoto(canvas *image.NRGBA, photoBytes []byte, ox, oy, w, h int) {
	srcImg, _, err := image.Decode(bytes.NewReader(photoBytes))
	if err != nil {
		return
	}
	sw, sh := srcImg.Bounds().Dx(), srcImg.Bounds().Dy()
	srcRatio := float64(sw) / float64(sh)
	dstRatio := float64(w) / float64(h)
	var cropW, cropH int
	if srcRatio > dstRatio {
		cropH = sh
		cropW = int(float64(sh) * dstRatio)
	} else {
		cropW = sw
		cropH = int(float64(sw) / dstRatio)
	}
	cropX := (sw - cropW) / 2
	cropY := (sh - cropH) / 2
	for y := 0; y < h; y++ {
		sy := cropY + (y*cropH)/h
		for x := 0; x < w; x++ {
			sx := cropX + (x*cropW)/w
			r, g, b, a := srcImg.At(sx, sy).RGBA()
			canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
}

// fetchThumbnail downloads the user's profile photo for embedding in the
// pass bundle. Best-effort — if it fails, the pass still generates but
// without the thumbnail. The photo-cdn returns the source bytes; we pass
// them through (PNG container preferred for thumbnail.png filename, but
// JPG inside a .png file works too — Wallet auto-detects).
func fetchThumbnail(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("photo-cdn %d", res.StatusCode)
	}
	// Cap at 500KB — Wallet rejects passes over ~640KB total.
	return io.ReadAll(io.LimitReader(res.Body, 500*1024))
}

func fetchCard(ctx context.Context, apiBase, id, slug string) (*card, error) {
	url := apiBase
	if id != "" {
		url += "/v1/cards/" + id
	} else {
		url += "/v1/c/" + slug
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vcard-api fetch: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("vcard-api %d: %s", res.StatusCode, string(body))
	}
	var c card
	if err := json.NewDecoder(res.Body).Decode(&c); err != nil {
		return nil, fmt.Errorf("decode card: %w", err)
	}
	return &c, nil
}

func buildPass(c *card, passTypeID, teamID, webBase string, embeddedPhoto []byte) pkpass.Pass {
	bg, fg, lbl := templateColors(c.Template, c.CustomColor)

	// Layout decisions, by region:
	//
	//   header (top, small):   no logoText, no headerFields → JUST the
	//                          logo.png tile. Keeps the area above the
	//                          strip clean so the photo isn't crowded
	//                          out of frame.
	//   primary fields:        EMPTY — primary lives RIGHT ABOVE the
	//                          strip image in eventTicket layout and Apple
	//                          draws it big. Putting the name there made
	//                          the strip's photo look like it was being
	//                          captioned ("name on face").
	//   strip:                 photo + brand logo composite (renderHeroStrip).
	//   secondary fields:      Name (col 1, prominent), Title (col 2). Below strip.
	//   auxiliary fields:      Company, Phone, Email (3 cols).
	//   back fields:           Full list of emails/phones + profile URL.
	secondary := []pkpass.Field{
		{Key: "name", Label: strings.ToUpper(c.Label), Value: c.Name},
	}
	if c.Title != "" {
		secondary = append(secondary, pkpass.Field{Key: "title", Label: "TITLE", Value: c.Title})
	}

	aux := []pkpass.Field{}
	if c.Company != "" {
		aux = append(aux, pkpass.Field{Key: "company", Label: "COMPANY", Value: c.Company})
	}
	if len(c.Phones) > 0 {
		aux = append(aux, pkpass.Field{Key: "phone", Label: "PHONE", Value: c.Phones[0]})
	}
	if len(c.Emails) > 0 {
		aux = append(aux, pkpass.Field{Key: "email", Label: "EMAIL", Value: c.Emails[0]})
	}

	back := []pkpass.Field{}
	for i, e := range c.Emails {
		back = append(back, pkpass.Field{Key: fmt.Sprintf("email%d", i), Label: "Email", Value: e})
	}
	for i, p := range c.Phones {
		back = append(back, pkpass.Field{Key: fmt.Sprintf("phone%d", i), Label: "Phone", Value: p})
	}
	if c.Slug != "" {
		back = append(back, pkpass.Field{Key: "profile", Label: "Profile", Value: webBase + "/c/" + c.Slug})
	}

	// vCard payload — caller passes the photo bytes (already fetched for
	// the strip render) so we can embed a small JPEG thumbnail directly in
	// the QR. iOS Camera does NOT fetch remote PHOTO;VALUE=uri URIs when
	// saving from a scanned QR — only embedded photos appear in the
	// saved contact.
	qrMsg := buildVCardText(c, webBase, embeddedPhoto)

	pass := pkpass.Pass{
		FormatVersion:      1,
		PassTypeIdentifier: passTypeID,
		SerialNumber:       c.Slug,
		TeamIdentifier:     teamID,
		OrganizationName:   "Dynolabs",
		Description:        "Dynolabs vCard — " + c.Name,
		// No LogoText — keeps header area clean. Apple still shows the
		// logo.png tile on the left.
		ForegroundColor: fg,
		BackgroundColor: bg,
		LabelColor:      lbl,
		Barcodes: []pkpass.Barcode{{
			Format:          "PKBarcodeFormatQR",
			Message:         qrMsg,
			MessageEncoding: "iso-8859-1",
			// AltText intentionally omitted: the same name is already
			// rendered in secondaryFields right above the QR.
		}},
	}
	// storeCard instead of eventTicket: storeCard's strip slot is
	// 312×123pt (~2.54:1), almost exactly our 1125×432 canvas (~2.60:1).
	// eventTicket's slot is 320×84pt (~3.81:1) — that's why a circle
	// drawn in our canvas displayed as an oval (different horizontal vs
	// vertical scale to fit the slot).
	pass.StoreCard = &pkpass.Style{
		// PrimaryFields intentionally empty — keeps the strip uncluttered.
		SecondaryFields: secondary,
		AuxiliaryFields: aux,
		BackFields:      back,
	}
	return pass
}

// buildVCardText serializes a vCard 3.0 string for the QR payload.
//
// Critical bits that previous iterations got wrong (founder feedback from
// scanned-contact result):
//
//   • iOS Camera "Save to Contacts" uses N (structured name) as the
//     display source. Without N, it falls back to ORG → the saved
//     contact's name became "Dynolabs" instead of "Nehir Baysal". We now
//     emit both N and FN.
//   • Untyped URL is labeled "homepage" by iOS Contacts. The Dynolabs
//     profile URL is a work-related link, so we tag it TYPE=WORK.
//   • iOS Camera does NOT fetch PHOTO;VALUE=uri remote URIs when saving
//     contacts from a scanned QR — only EMBEDDED base64 photos show up
//     in the saved contact's avatar. If photoBytes is provided we embed
//     a small JPEG thumbnail (kept tiny so the QR remains scannable).
//
// Format kept compatible with the mobile client's lib/vcard.ts.
func buildVCardText(c *card, webBase string, embeddedPhoto []byte) string {
	var sb strings.Builder
	sb.WriteString("BEGIN:VCARD\r\n")
	sb.WriteString("VERSION:3.0\r\n")
	// N: structured name (last;first;middle;prefix;suffix). Split on
	// last whitespace. Fallback to ;<name>;;; (given-name only).
	last, first := splitName(c.Name)
	sb.WriteString("N:" + escapeVCard(last) + ";" + escapeVCard(first) + ";;;\r\n")
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
		sb.WriteString("URL;TYPE=WORK:" + escapeVCard(s.URL) + "\r\n")
	}
	if c.Slug != "" {
		sb.WriteString("URL;TYPE=WORK:" + escapeVCard(webBase+"/c/"+c.Slug) + "\r\n")
	}
	// Embed a small JPEG thumbnail directly so iOS Contacts shows the
	// face avatar after a QR-scan save. Folding (vCard 3.0 line-folding
	// rule) is applied per RFC 2425 §5.8.1: any line > 75 octets must be
	// continued by CRLF SPACE.
	if len(embeddedPhoto) > 0 {
		b64 := base64.StdEncoding.EncodeToString(embeddedPhoto)
		sb.WriteString(foldVCardLine("PHOTO;ENCODING=b;TYPE=JPEG:" + b64))
	}
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
}

// splitName splits "First Middle Last" into ("Last", "First Middle").
// Single-word names go to first-name with empty last-name.
func splitName(full string) (last, first string) {
	full = strings.TrimSpace(full)
	if full == "" {
		return "", ""
	}
	idx := strings.LastIndex(full, " ")
	if idx <= 0 {
		return "", full
	}
	return full[idx+1:], strings.TrimSpace(full[:idx])
}

// foldVCardLine folds a long property line per RFC 2425 §5.8.1: each
// continuation line starts with a single space. Returns the line with a
// trailing CRLF.
func foldVCardLine(line string) string {
	const max = 75
	if len(line) <= max {
		return line + "\r\n"
	}
	var b strings.Builder
	b.Grow(len(line) + len(line)/max*3)
	for i := 0; i < len(line); i += max {
		end := i + max
		if end > len(line) {
			end = len(line)
		}
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(line[i:end])
		b.WriteString("\r\n")
	}
	return b.String()
}

// thumbnailJPEG resizes raw image bytes (any decodable format) to a
// square JPEG sized for the vCard PHOTO embed. Target ≤ 2 KB so the
// total QR payload stays scannable on a typical phone display.
func thumbnailJPEG(src []byte, size int, quality int) ([]byte, error) {
	srcImg, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	sw, sh := srcImg.Bounds().Dx(), srcImg.Bounds().Dy()
	sz := sw
	if sh < sw {
		sz = sh
	}
	sx0 := (sw - sz) / 2
	sy0 := (sh - sz) / 2
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		sy := sy0 + (y*sz)/size
		for x := 0; x < size; x++ {
			sx := sx0 + (x*sz)/size
			r, g, b, a := srcImg.At(sx, sy).RGBA()
			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
			})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func escapeVCard(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `,`, `\,`, `;`, `\;`, "\n", `\n`, "\r", "")
	return r.Replace(s)
}

// templateColors returns rgb(...) strings for pass background, foreground, label.
// customColor wins regardless of template — the mobile app applies the user's
// picked color on every template, so the pass must match. Template only
// picks the default when no customColor was set.
func templateColors(template, customColor string) (bg, fg, lbl string) {
	if customColor != "" {
		r, g, b := hexToRGB(customColor)
		return fmt.Sprintf("rgb(%d,%d,%d)", r, g, b), "rgb(255,255,255)", "rgb(255,255,255)"
	}
	switch template {
	case "gradient":
		return "rgb(31,37,51)", "rgb(255,255,255)", "rgb(180,180,200)"
	case "glass":
		return "rgb(16,16,18)", "rgb(255,255,255)", "rgb(160,160,160)"
	case "custom":
		return "rgb(10,102,194)", "rgb(255,255,255)", "rgb(255,255,255)"
	default: // mono
		return "rgb(11,11,15)", "rgb(255,255,255)", "rgb(160,160,160)"
	}
}

// iconPNG returns a tiny solid-color PNG. Apple Wallet REQUIRES icon.png
// and icon@2x.png even though we never display them next to a QR-only pass;
// returning an empty file fails validation. v1 ships a brand-coloured square.
func iconPNG(size int, template, customColor string) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	bgHex := "#0B0B0F"
	if customColor != "" {
		bgHex = customColor
	} else {
		switch template {
		case "gradient":
			bgHex = "#1F2533"
		case "glass":
			bgHex = "#101012"
		case "custom":
			bgHex = "#0A66C2"
		}
	}
	r, g, b := hexToRGB(bgHex)
	c := color.NRGBA{R: r, G: g, B: b, A: 255}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.SetNRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func hexToRGB(h string) (uint8, uint8, uint8) {
	if strings.HasPrefix(h, "#") {
		h = h[1:]
	}
	if len(h) != 6 {
		return 11, 11, 15
	}
	var rgb [3]uint8
	for i := 0; i < 3; i++ {
		v, err := parseHexByte(h[2*i : 2*i+2])
		if err != nil {
			return 11, 11, 15
		}
		rgb[i] = v
	}
	return rgb[0], rgb[1], rgb[2]
}

func parseHexByte(s string) (uint8, error) {
	var n uint8
	_, err := fmt.Sscanf(s, "%x", &n)
	return n, err
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
