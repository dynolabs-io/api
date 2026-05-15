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
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"  // register GIF decoder for image.Decode
	_ "image/jpeg" // register JPEG decoder — photo-cdn returns JPEGs
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
	WalletStyle  string       `json:"walletStyle"` // photoStrip | logoStrip
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
		// ?style= query param overrides the card's saved wallet_style for
		// this request only. Useful for previewing all layouts without
		// editing the card.
		if styleOverride := r.URL.Query().Get("style"); styleOverride != "" {
			c.WalletStyle = styleOverride
		}
		// Log every pass build with the slug requested and the name that
		// will appear in the pass. This is how we diagnose "wallet shows
		// wrong card" — proves which card the app actually asked for.
		slog.Info("pass requested",
			"slug-requested", slug, "cardId-requested", cardID,
			"name-served", c.Name, "slug-served", c.Slug,
			"ua", r.UserAgent())

		pass := buildPass(c, passTypeID, teamID, webBase)

		// Fetch brand logo + profile photo once.
		var brandLogoBytes, photoBytes []byte
		if c.BrandLogoURL != "" {
			if b, err := fetchThumbnail(r.Context(), c.BrandLogoURL); err == nil && len(b) > 0 {
				brandLogoBytes = b
			} else if err != nil {
				slog.Warn("brand logo fetch failed", "err", err, "url", c.BrandLogoURL)
			}
		}
		if c.PhotoURL != "" {
			if p, err := fetchThumbnail(r.Context(), c.PhotoURL); err == nil && len(p) > 0 {
				photoBytes = p
			} else if err != nil {
				slog.Warn("photo fetch failed", "err", err, "url", c.PhotoURL)
			}
		}

		// Icon + logo: the user's brand logo if uploaded, else a
		// brand-color tile (same as before). The brand logo gives the
		// pass an identity in Wallet's lock-screen icon strip.
		var iconAsset, logoAsset []byte
		if len(brandLogoBytes) > 0 {
			// Apple wants square icon (29pt @2x = 58px, @3x = 87px) and
			// rectangular logo (max 160pt × 50pt @2x = 320×100, @3x = 480×150).
			// Resize the brand logo for each.
			if ic, err := resizeSquare(brandLogoBytes, 87); err == nil {
				iconAsset = ic
			}
			if lg, err := fitToCanvasTransparent(brandLogoBytes, 480, 150); err == nil {
				logoAsset = lg
			}
		}
		if iconAsset == nil {
			iconAsset = iconPNG(87, c.Template, c.CustomColor)
		}
		if logoAsset == nil {
			logoAsset = iconPNG(160, c.Template, c.CustomColor)
		}
		assets := map[string][]byte{
			"icon.png":    iconAsset,
			"icon@2x.png": iconAsset,
			"icon@3x.png": iconAsset,
			"logo.png":    logoAsset,
			"logo@2x.png": logoAsset,
		}

		// Strip image fills the top ~25% of the pass front, full width.
		// Two named styles: photoStrip (profile photo) | logoStrip (brand bg + logo).
		// Any other (or empty) value falls back to photoStrip if a photo
		// exists, else logoStrip — so legacy DB values don't produce blank passes.
		strip := c.WalletStyle
		if strip != "photoStrip" && strip != "logoStrip" {
			if len(photoBytes) > 0 {
				strip = "photoStrip"
			} else {
				strip = "logoStrip"
			}
		}
		if strip == "photoStrip" && len(photoBytes) == 0 {
			strip = "logoStrip"
		}
		switch strip {
		case "photoStrip":
			if s, err := fitToCanvas(photoBytes, 1125, 432); err == nil {
				assets["strip.png"] = s
				assets["strip@2x.png"] = s
			}
		case "logoStrip":
			if s, err := renderLogoStrip(c, brandLogoBytes, 1125, 432); err == nil {
				assets["strip.png"] = s
				assets["strip@2x.png"] = s
			}
		}
		// Thumbnail also gets the profile photo so it shows in lock-screen
		// notifications alongside the icon.
		if len(photoBytes) > 0 {
			if t, err := resizeSquare(photoBytes, 180); err == nil {
				assets["thumbnail.png"] = t
				assets["thumbnail@2x.png"] = t
			}
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

// renderBrandedArtwork composes a branded image: brand-color background
// with a circular profile photo top-center and the company name at bottom
// in large text. Used by walletStyle=posterBrand.
func renderBrandedArtwork(c *card, photoBytes []byte, w, h int) ([]byte, error) {
	// Background color
	bgHex := "#0B0B0F"
	if c.CustomColor != "" {
		bgHex = c.CustomColor
	}
	br, bg, bb := hexToRGB(bgHex)
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			canvas.SetNRGBA(x, y, color.NRGBA{R: br, G: bg, B: bb, A: 255})
		}
	}
	// Circular photo at top-center (occupying ~40% of canvas height)
	if len(photoBytes) > 0 {
		photoSize := h * 4 / 10
		if photoSize > w*7/10 {
			photoSize = w * 7 / 10
		}
		photoImg, _, err := image.Decode(bytes.NewReader(photoBytes))
		if err == nil {
			// Crop to square first
			sw, sh := photoImg.Bounds().Dx(), photoImg.Bounds().Dy()
			sz := sw
			if sh < sw {
				sz = sh
			}
			sx0 := (sw - sz) / 2
			sy0 := (sh - sz) / 2
			ox := (w - photoSize) / 2
			oy := h*15/100
			radius := photoSize / 2
			cx := ox + radius
			cy := oy + radius
			for y := 0; y < photoSize; y++ {
				for x := 0; x < photoSize; x++ {
					dx := (ox + x) - cx
					dy := (oy + y) - cy
					if dx*dx+dy*dy > radius*radius {
						continue // outside circle
					}
					sx := sx0 + (x*sz)/photoSize
					sy := sy0 + (y*sz)/photoSize
					r, g, b, a := photoImg.At(sx, sy).RGBA()
					canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
						R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8),
					})
				}
			}
		}
	}
	// We could draw text here but Go's stdlib font rendering is limited.
	// Leaving text to Apple's pass.json field overlay is cleaner.
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// resizeSquare crops to a centered square then resizes to size×size.
func resizeSquare(src []byte, size int) ([]byte, error) {
	return fitToCanvas(src, size, size)
}

// fitToCanvasTransparent resizes src to fit INSIDE w×h preserving aspect
// (no crop) and centers it on a transparent canvas. Used for the brand
// logo where we don't want to distort wide/short logos.
func fitToCanvasTransparent(src []byte, w, h int) ([]byte, error) {
	srcImg, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	sw, sh := srcImg.Bounds().Dx(), srcImg.Bounds().Dy()
	srcRatio := float64(sw) / float64(sh)
	dstRatio := float64(w) / float64(h)
	var contentW, contentH int
	if srcRatio > dstRatio {
		// Logo is wider than canvas — fit by width
		contentW = w
		contentH = int(float64(w) / srcRatio)
	} else {
		contentH = h
		contentW = int(float64(h) * srcRatio)
	}
	ox := (w - contentW) / 2
	oy := (h - contentH) / 2
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < contentH; y++ {
		sy := (y * sh) / contentH
		for x := 0; x < contentW; x++ {
			sx := (x * sw) / contentW
			r, g, b, a := srcImg.At(sx, sy).RGBA()
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

// renderLogoStrip composes the brand color as background + the brand
// logo (if available) centered. Used for walletStyle=logoStrip.
func renderLogoStrip(c *card, logoBytes []byte, w, h int) ([]byte, error) {
	bgHex := "#0B0B0F"
	if c.CustomColor != "" {
		bgHex = c.CustomColor
	} else {
		switch c.Template {
		case "gradient":
			bgHex = "#1F2533"
		case "glass":
			bgHex = "#101012"
		}
	}
	br, bg, bb := hexToRGB(bgHex)
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			canvas.SetNRGBA(x, y, color.NRGBA{R: br, G: bg, B: bb, A: 255})
		}
	}
	// Place logo centered, occupying ~70% of strip height
	if len(logoBytes) > 0 {
		logoImg, _, err := image.Decode(bytes.NewReader(logoBytes))
		if err == nil {
			targetH := h * 70 / 100
			lw, lh := logoImg.Bounds().Dx(), logoImg.Bounds().Dy()
			targetW := lw * targetH / lh
			if targetW > w*80/100 {
				targetW = w * 80 / 100
				targetH = lh * targetW / lw
			}
			ox := (w - targetW) / 2
			oy := (h - targetH) / 2
			for y := 0; y < targetH; y++ {
				sy := (y * lh) / targetH
				for x := 0; x < targetW; x++ {
					sx := (x * lw) / targetW
					r, g, bb2, a := logoImg.At(sx, sy).RGBA()
					if a>>8 < 16 {
						continue
					}
					canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
						R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(bb2 >> 8), A: uint8(a >> 8),
					})
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

func buildPass(c *card, passTypeID, teamID, webBase string) pkpass.Pass {
	bg, fg, lbl := templateColors(c.Template, c.CustomColor)

	primary := []pkpass.Field{{Key: "name", Value: c.Name, Label: c.Label}}

	secondary := []pkpass.Field{}
	if c.Title != "" {
		secondary = append(secondary, pkpass.Field{Key: "title", Label: "TITLE", Value: c.Title})
	}
	if c.Company != "" {
		secondary = append(secondary, pkpass.Field{Key: "company", Label: "COMPANY", Value: c.Company})
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

	// QR encodes the FULL vCard text (BEGIN:VCARD … END:VCARD) — same
	// payload the app shows. Recipient's default camera reads it offline,
	// offers Save to Contacts directly. Profile URL added as a URL field
	// so they can also tap into the web page.
	qrMsg := buildVCardText(c, webBase)

	pass := pkpass.Pass{
		FormatVersion:      1,
		PassTypeIdentifier: passTypeID,
		SerialNumber:       c.Slug,
		TeamIdentifier:     teamID,
		OrganizationName:   "Dynolabs",
		Description:        "Dynolabs vCard — " + c.Name,
		LogoText:           c.Name,
		ForegroundColor:    fg,
		BackgroundColor:    bg,
		LabelColor:         lbl,
		Barcodes: []pkpass.Barcode{{
			Format:          "PKBarcodeFormatQR",
			Message:         qrMsg,
			MessageEncoding: "iso-8859-1",
			AltText:         strings.TrimSpace(c.Name),
		}},
	}
	style := &pkpass.Style{
		PrimaryFields:   primary,
		SecondaryFields: secondary,
		BackFields:      back,
	}
	// Add auxiliary fields populated from card data so the middle of the
	// pass isn't empty. Apple shows up to 4 auxiliary fields in a row.
	aux := []pkpass.Field{}
	if len(c.Phones) > 0 {
		aux = append(aux, pkpass.Field{Key: "phone", Label: "PHONE", Value: c.Phones[0]})
	}
	if len(c.Emails) > 0 {
		aux = append(aux, pkpass.Field{Key: "email", Label: "EMAIL", Value: c.Emails[0]})
	}
	style.AuxiliaryFields = aux

	// Single eventTicket layout for all wallet styles — the visual
	// difference comes from the strip image, not the pass style.
	pass.EventTicket = style
	return pass
}

// buildVCardText serializes a vCard 3.0 string identical to the mobile
// client's lib/vcard.ts output, so the wallet pass QR matches the in-app QR.
func buildVCardText(c *card, webBase string) string {
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
	if c.Slug != "" {
		sb.WriteString("URL:" + escapeVCard(webBase+"/c/"+c.Slug) + "\r\n")
	}
	if c.PhotoURL != "" {
		sb.WriteString("PHOTO;VALUE=uri:" + c.PhotoURL + "\r\n")
	}
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
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
