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
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	_ "image/gif" // register GIF decoder for image.Decode
	"image/jpeg" // encoder/decoder — photo-cdn returns JPEGs; we also re-encode for the .vcf embed
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
	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

//go:embed assets/DejaVuSans.ttf
var fontRegularTTF []byte

//go:embed assets/DejaVuSans-Bold.ttf
var fontBoldTTF []byte

var (
	fontRegular *opentype.Font
	fontBold    *opentype.Font
)

var transparent1x1PNG []byte

func init() {
	var err error
	if fontRegular, err = opentype.Parse(fontRegularTTF); err != nil {
		panic("parse regular font: " + err.Error())
	}
	if fontBold, err = opentype.Parse(fontBoldTTF); err != nil {
		panic("parse bold font: " + err.Error())
	}
	// 1×1 fully-transparent PNG — used as logo.png to suppress Apple's
	// header logo tile so we don't double-print the company brand
	// (the strip itself carries the small top-left logo).
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	img.SetNRGBA(0, 0, color.NRGBA{0, 0, 0, 0})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic("encode transparent1x1: " + err.Error())
	}
	transparent1x1PNG = buf.Bytes()
}

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
	// Public URL base for the .vcf endpoint that the online-mode QR
	// resolves to. The recipient's iPhone fetches this URL when they tap
	// the URL in the iOS Camera preview; the server returns a vCard with
	// the full-resolution photo embedded. Defaults to the production host.
	vcfURLBase := getenv("VCARD_URL_BASE", "https://api.dynolabs.io")
	// Wallet web-service base URL — where iOS Wallet calls back for
	// push updates. Lives in vcard-api (which has the DB + ingress
	// reach). Token must match WALLET_WEBSERVICE_TOKEN there.
	walletBase := getenv("WALLET_WEBSERVICE_URL", "https://api.dynolabs.io")
	walletToken := getenv("WALLET_WEBSERVICE_TOKEN", "")
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
		var cardID, slug, mode string
		if r.Method == http.MethodGet {
			cardID = r.URL.Query().Get("cardId")
			slug = r.URL.Query().Get("slug")
			mode = r.URL.Query().Get("mode")
		} else {
			var body struct {
				CardID string `json:"cardId"`
				Slug   string `json:"slug"`
				Mode   string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
				return
			}
			cardID, slug, mode = body.CardID, body.Slug, body.Mode
		}
		// Mode = "offline" or "online" (default).
		//   online  → QR contains only the .vcf URL. Recipient online →
		//             Safari loads .vcf → contact saves with FULL-RES photo.
		//   offline → QR contains the full vCard text minus PHOTO.
		//             Recipient saves the basic contact instantly, no network.
		// Each mode gets a distinct pass serial + description so they can
		// coexist in Wallet without collision.
		if mode != "offline" {
			mode = "online"
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
			"mode", mode,
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

		pass := buildPass(c, passTypeID, teamID, webBase, vcfURLBase, mode)
		if walletToken != "" {
			pass.WebServiceURL = walletBase
			pass.AuthenticationToken = walletToken
		}

		// Apple's "logo" header slot (top-left of the pass) is a small
		// rectangular chip rendered ABOVE the strip. The "icon" is a
		// square (29pt) shown wherever the pass appears in lists /
		// lock-screen.
		//
		// Build 147: logo.png is now a TRANSPARENT 1×1 placeholder so
		// Apple's header tile renders nothing — the strip carries the
		// only company-logo glyph (small, top-left of the strip), which
		// is what the founder standardized. icon.png keeps the brand
		// logo so lock-screen/list rows still identify the pass.
		iconAsset := iconPNG(87, c.Template, c.CustomColor)
		if len(brandLogoBytes) > 0 {
			if ic, err := fitLogoToTile(brandLogoBytes, 87, 87, c); err == nil {
				iconAsset = ic
			}
		}
		assets := map[string][]byte{
			"icon.png":    iconAsset,
			"icon@2x.png": iconAsset,
			"icon@3x.png": iconAsset,
			"logo.png":    transparent1x1PNG,
			"logo@2x.png": transparent1x1PNG,
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

	// /v/<slug>.vcf — serves a vCard 3.0 file with the FULL-RESOLUTION
	// photo embedded as base64. The online-mode QR resolves to this URL;
	// the recipient's Safari downloads the .vcf, iOS shows the Contact
	// Card sheet, "Add to Contacts" saves the contact WITH the photo.
	//
	// This is the only path that delivers a high-res photo to a saved
	// iOS contact via QR scan — iOS Camera deliberately won't fetch
	// PHOTO;VALUE=URI references at save time, so we route through Safari
	// (which is an explicit network action by the user, allowed).
	// /v/{slug} serves the vCard. We don't put .vcf in the URL because
	// Go 1.22's ServeMux pattern wildcards must own the entire path
	// segment — `{slug}.vcf` is rejected. Safari recognises the response
	// as a vCard from the `Content-Type: text/vcard` header alone (the
	// filename comes from Content-Disposition).
	mux.HandleFunc("GET /v/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if slug == "" {
			http.Error(w, "slug required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		c, err := fetchCard(ctx, apiBase, "", slug)
		if err != nil {
			slog.Warn("vcf fetch card failed", "err", err, "slug", slug, "ua", r.UserAgent())
			http.Error(w, "card not found", http.StatusNotFound)
			return
		}
		// Fetch + re-encode the photo to a sensible size. 512×512 q70 ≈
		// 25 KB — looks crisp on iPhone contact detail (120pt @ 3x = 360
		// pixels rendered), and the .vcf response is still tiny by web
		// standards.
		var photoEmbed []byte
		if c.PhotoURL != "" && strings.HasPrefix(c.PhotoURL, "http") {
			if raw, err := fetchThumbnail(r.Context(), c.PhotoURL); err == nil && len(raw) > 0 {
				if enc, err := reencodeJPEG(raw, 512, 70); err == nil {
					photoEmbed = enc
				} else {
					slog.Warn("vcf photo reencode failed", "err", err)
				}
			} else if err != nil {
				slog.Warn("vcf photo fetch failed", "err", err, "url", c.PhotoURL)
			}
		}
		body := buildVCardWithEmbeddedPhoto(c, webBase, photoEmbed)
		w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="%s.vcf"`, sanitizeFilename(c.Name)))
		w.Header().Set("Cache-Control", "private, max-age=60")
		_, _ = w.Write([]byte(body))
		slog.Info("vcf served", "slug", slug, "name", c.Name, "hasPhoto", len(photoEmbed) > 0, "bytes", len(body))
	})

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

// fitLogoToTile renders the brand logo onto a w×h PNG with the card's
// brand color as background. Aspect-preserved fit (no crop). Used for
// the Apple Wallet header icon + logo slots so the company brand shows
// in pass lists / lock-screen notifications.
func fitLogoToTile(src []byte, w, h int, c *card) ([]byte, error) {
	srcImg, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	br, bg, bb := hexToRGB(brandColorHex(c))
	canvas := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			canvas.SetNRGBA(x, y, color.NRGBA{R: br, G: bg, B: bb, A: 255})
		}
	}
	sw, sh := srcImg.Bounds().Dx(), srcImg.Bounds().Dy()
	if sw == 0 || sh == 0 {
		return nil, fmt.Errorf("empty logo")
	}
	srcRatio := float64(sw) / float64(sh)
	dstRatio := float64(w) / float64(h)
	var cw, ch int
	if srcRatio > dstRatio {
		cw = w * 86 / 100
		ch = int(float64(cw) / srcRatio)
	} else {
		ch = h * 86 / 100
		cw = int(float64(ch) * srcRatio)
	}
	px := (w - cw) / 2
	py := (h - ch) / 2
	for y := 0; y < ch; y++ {
		sy := (y * sh) / ch
		for x := 0; x < cw; x++ {
			sx := (x * sw) / cw
			r, g, b, a := srcImg.At(sx, sy).RGBA()
			if a>>8 < 16 {
				continue
			}
			canvas.SetNRGBA(px+x, py+y, color.NRGBA{
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

// renderHeroStrip composes the front banner of the Wallet pass.
//
// Build 147 layout (founder-picked option 2 + blank-header):
//   • Brand-color background fills the full 1125×432 canvas.
//   • Small company logo glyph top-left of the strip (the ONE place
//     the brand logo appears now — Apple's header tile is blanked
//     via a 1×1 transparent logo.png).
//   • Photo medallion CENTERED horizontally, sits in upper area.
//   • Below the medallion, 3 CENTERED lines:
//       NAME    (big bold)
//       Title   (medium)
//       Company (medium)
//   • Foreground text color picked by luma for readability.
//   • Apple's auxiliaryFields still carry Phone/Email below the strip
//     (those need to stay tappable for tel:/mailto:).
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
	fg := readableFG(br, bg, bb)
	fgSoft := softFG(br, bg, bb)

	// Photo medallion: bigger (founder Build 167 feedback — was 238,
	// now 270 = +13%). Centered horizontally, top-aligned with very
	// small inset so it sits high and the 3 text lines fit below.
	photoDiam := h * 63 / 100 // ~272 on 432 canvas
	if photoDiam > w*28/100 {
		photoDiam = w * 28 / 100
	}
	photoTop := h * 1 / 100 // ~4 — close to top edge
	photoX := (w - photoDiam) / 2
	if hasPhoto {
		drawCircularPhoto(canvas, photoBytes, photoX, photoTop, photoDiam)
	}

	// Small company logo top-left — moved HIGHER (founder said it had
	// drifted down) and slightly larger so it's not lost.
	if hasLogo {
		logoBoxH := h * 16 / 100 // ~70 on 432 (was ~60)
		logoBoxW := w * 13 / 100 // ~146 on 1125 (was ~124)
		logoInsetY := h * 1 / 100 // ~4 — tight to top edge
		logoInsetX := w * 1 / 100 // ~12 — tight to left edge
		drawLogoFit(canvas, logoBytes, logoInsetX, logoInsetY, logoBoxW, logoBoxH)
	}

	// 3 centered text lines BELOW the medallion — BIGGER fonts so they
	// visibly dominate Apple's auxiliary phone/email row underneath.
	cursorY := photoTop + photoDiam + h*2/100 // small gap after photo
	textW := w * 92 / 100
	textX := (w - textW) / 2

	if name := strings.TrimSpace(c.Name); name != "" {
		drawTextCentered(canvas, name, fontBold, 58, textX, cursorY, textW, fg)
		cursorY += 66
	}
	if title := strings.TrimSpace(c.Title); title != "" {
		drawTextCentered(canvas, title, fontRegular, 36, textX, cursorY, textW, fgSoft)
		cursorY += 42
	}
	if company := strings.TrimSpace(c.Company); company != "" {
		drawTextCentered(canvas, company, fontRegular, 36, textX, cursorY, textW, fgSoft)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawTextCentered renders text horizontally centered within the
// rectangle (x, y, x+w). Truncates with an ellipsis when too wide.
func drawTextCentered(canvas *image.NRGBA, s string, ttf *opentype.Font, size float64, x, y, w int, fg color.NRGBA) {
	face, err := opentype.NewFace(ttf, &opentype.FaceOptions{
		Size:    size,
		DPI:     72,
		Hinting: font.HintingFull,
	})
	if err != nil {
		return
	}
	defer face.Close()

	d := &font.Drawer{
		Dst:  canvas,
		Src:  image.NewUniform(fg),
		Face: face,
	}
	display := s
	if d.MeasureString(display).Round() > w {
		for len(display) > 1 && d.MeasureString(display+"…").Round() > w {
			display = display[:len(display)-1]
		}
		display += "…"
	}
	textW := d.MeasureString(display).Round()
	startX := x + (w-textW)/2
	metrics := face.Metrics()
	baseline := y + metrics.Ascent.Round()
	d.Dot = fixed.P(startX, baseline)
	d.DrawString(display)
}

// readableFG picks black or white text for the given brand color
// using Rec.709 luma. Matches the mobile app's isLight() function so
// strip text reads consistently with what the user designed in-app.
func readableFG(r, g, b uint8) color.NRGBA {
	y := 0.2126*float64(r) + 0.7152*float64(g) + 0.0722*float64(b)
	if y > 160 {
		return color.NRGBA{R: 0x0B, G: 0x0B, B: 0x0F, A: 0xFF}
	}
	return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
}

// softFG = readableFG dimmed to ~75% — for title/company secondary
// text below the main name.
func softFG(r, g, b uint8) color.NRGBA {
	fg := readableFG(r, g, b)
	if fg.R == 0xFF {
		return color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xCC}
	}
	return color.NRGBA{R: 0x0B, G: 0x0B, B: 0x0F, A: 0xB3}
}

// drawLogoFit fits the logo bytes inside (ox, oy, w, h) preserving aspect.
// Transparent pixels (a < 16) are skipped so the brand color shows through.
func drawLogoFit(canvas *image.NRGBA, logoBytes []byte, ox, oy, w, h int) {
	if w <= 0 || h <= 0 {
		return
	}
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

// drawCircularPhoto draws a center-cover-cropped photo inside a circle at
// (ox, oy) with the given diameter. Pixels outside the circle are left
// untouched so the underlying brand color shows through. A thick white
// ring (12px) frames the photo for medallion contrast against any brand
// color background.
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
	const ring = 14
	ringInner := radius - ring
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
			// Photo inside the ring, scaled to (radius-ring)*2 source range.
			inDiam := diam - 2*ring
			sx := sx0 + ((x - ring) * sz) / inDiam
			sy := sy0 + ((y - ring) * sz) / inDiam
			if sx < 0 || sx >= sw || sy < 0 || sy >= sh {
				continue
			}
			r, g, b, a := photoImg.At(sx, sy).RGBA()
			canvas.SetNRGBA(ox+x, oy+y, color.NRGBA{
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

func buildPass(c *card, passTypeID, teamID, webBase, vcfURLBase, mode string) pkpass.Pass {
	bg, fg, lbl := templateColors(c.Template, c.CustomColor)

	// Layout decisions, by region (Build 146):
	//
	//   header (top, small):   logo.png tile (the ONE place the brand
	//                          logo appears on the front)
	//   primary fields:        EMPTY — Apple overlays primary fields ON
	//                          the strip image in storeCard. We render
	//                          our own text on the strip; putting fields
	//                          here would double-print on top.
	//   strip:                 FULL CARD VIEW (Build 146 — renderHeroStrip
	//                          draws Name + Title + Company as text on
	//                          the left, photo medallion on the right —
	//                          mirrors the in-app card layout).
	//   secondary fields:      EMPTY (name/title/company are on the strip)
	//   auxiliary fields:      Phone + Email (kept as Apple fields so the
	//                          values are tappable for tel:/mailto: —
	//                          strip-rendered text isn't tappable).
	//   back fields:           Title + Company + full phone/email lists
	//                          + profile URL (always-on copy for users
	//                          who flip the pass over).
	primary := []pkpass.Field{}
	secondary := []pkpass.Field{}

	aux := []pkpass.Field{}
	if len(c.Phones) > 0 {
		aux = append(aux, pkpass.Field{Key: "phone", Label: "PHONE", Value: c.Phones[0]})
	}
	if len(c.Emails) > 0 {
		aux = append(aux, pkpass.Field{Key: "email", Label: "EMAIL", Value: c.Emails[0]})
	}

	back := []pkpass.Field{}
	if c.Title != "" {
		back = append(back, pkpass.Field{Key: "title", Label: "Title", Value: c.Title})
	}
	if c.Company != "" {
		back = append(back, pkpass.Field{Key: "company", Label: "Company", Value: c.Company})
	}
	for i, e := range c.Emails {
		back = append(back, pkpass.Field{Key: fmt.Sprintf("email%d", i), Label: "Email", Value: e})
	}
	for i, p := range c.Phones {
		back = append(back, pkpass.Field{Key: fmt.Sprintf("phone%d", i), Label: "Phone", Value: p})
	}
	if c.Slug != "" {
		back = append(back, pkpass.Field{Key: "profile", Label: "Profile", Value: webBase + "/c/" + c.Slug})
	}

	// QR payload depends on mode:
	//   online  → just the .vcf URL. The recipient's Safari fetches it
	//             and iOS Contacts imports the vCard (with the full-res
	//             embedded photo) — guaranteed working when online.
	//   offline → vCard text with NO PHOTO line. iOS Camera saves the
	//             contact instantly, no network needed. No photo on the
	//             saved contact (Apple won't fetch URIs and we don't
	//             embed bytes to keep the QR scannable).
	var qrMsg string
	if mode == "online" {
		// No .vcf suffix — server route is /v/{slug} (Go 1.22 mux
		// doesn't accept literal-suffix wildcards). iOS recognises the
		// response as a vCard from Content-Type alone.
		qrMsg = vcfURLBase + "/v/" + c.Slug
	} else {
		qrMsg = buildVCardText(c, webBase)
	}

	// Serial + description must differ per mode so both passes can live
	// in Apple Wallet at the same time. Apple Wallet dedupes by
	// (passTypeIdentifier, serialNumber).
	modeLabel := "Offline (basic)"
	if mode == "online" {
		modeLabel = "Online (rich)"
	}

	pass := pkpass.Pass{
		FormatVersion:      1,
		PassTypeIdentifier: passTypeID,
		SerialNumber:       c.Slug + "-" + mode,
		TeamIdentifier:     teamID,
		OrganizationName:   "Dynolabs",
		Description:        "Dynolabs vCard — " + c.Name + " · " + modeLabel,
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
		PrimaryFields:   primary,
		SecondaryFields: secondary,
		AuxiliaryFields: aux,
		BackFields:      back,
	}
	return pass
}

// buildVCardText serializes the OFFLINE-mode vCard 3.0 string.
//
//   • N (structured name) — iOS Camera uses N for the saved contact name
//     (fallback to ORG would name the contact "Dynolabs").
//   • URLs carry TYPE=WORK so iOS labels them "work" not "homepage".
//   • NO PHOTO line: iOS Camera does not fetch remote URIs from a scanned
//     QR (verified — gets initials avatar), and embedding base64 here
//     would make the QR unreadable. Offline mode is text-only by design.
//     For photo-on-save, use the online-mode QR which resolves to the
//     /v/<slug>.vcf endpoint (full-res embedded photo via HTTP).
//
// Byte-identical to the mobile client's lib/vcard.ts offline output.
func buildVCardText(c *card, webBase string) string {
	var sb strings.Builder
	sb.WriteString("BEGIN:VCARD\r\n")
	sb.WriteString("VERSION:3.0\r\n")
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
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
}

// buildVCardWithEmbeddedPhoto returns a vCard 3.0 string with the
// profile photo embedded as base64 JPEG. This is what the /v/<slug>.vcf
// endpoint returns: the recipient's iOS Contacts imports it via Safari,
// so the QR-density constraint that forced offline-mode to drop PHOTO
// does NOT apply here — we can include the full-resolution image.
//
// Lines exceeding 75 octets are folded per RFC 2425 §5.8.1 (continuation
// lines start with a single space) so iOS's vCard parser accepts the
// embedded photo regardless of size.
func buildVCardWithEmbeddedPhoto(c *card, webBase string, photoBytes []byte) string {
	base := strings.TrimSuffix(buildVCardText(c, webBase), "END:VCARD\r\n")
	var sb strings.Builder
	sb.WriteString(base)
	if len(photoBytes) > 0 {
		b64 := base64.StdEncoding.EncodeToString(photoBytes)
		sb.WriteString(foldVCardLine("PHOTO;ENCODING=b;TYPE=JPEG:" + b64))
	}
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
}

// foldVCardLine folds a long property line per RFC 2425 §5.8.1.
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

// reencodeJPEG decodes any image (jpeg/png/gif), center-crops to a
// square at `size` pixels, and re-encodes as JPEG at the given quality.
// Used by the /v/<slug>.vcf endpoint to size the embedded photo
// appropriately — full-res on contact detail but not multi-MB.
func reencodeJPEG(src []byte, size int, quality int) ([]byte, error) {
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

// sanitizeFilename produces a safe Content-Disposition filename from a
// person's name (no slashes, no quotes, fallback to "card").
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "card"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '-', r == '_':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "card"
	}
	return b.String()
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
