// Package enrich — LinkedIn vanity-page enrichment routed through the
// iogrid bandwidth proxy (SOCKS5+TLS over TLS-passthrough at
// proxy.iogrid.org:443).
//
// Endpoint:
//
//	POST /v1/enrich/linkedin  body {"vanity": "satyanadella"}
//	                          resp {"title", "company", "companyDomain",
//	                                "linkedinUrl", "photoUrl"}
//
// Why: Apollo's free tier caps at 50 lookups/month and returns empty
// payloads without a paid plan. LinkedIn's own profile pages already
// carry name/title/company/photo in the static SSR markup
// (og:title + og:image meta tags). The blocker is the per-datacenter-IP
// rate limit LinkedIn applies to AWS/Hetzner egress — vcard-api running
// on a Sovereign Hetzner node hits it within minutes. iogrid's
// residential-proxy mesh sidesteps that by routing the GET through a
// home-IP provider.
//
// Wire format (NON-TRIVIAL — see iogrid issue #265):
//
//  1. tls.Dial proxy.iogrid.org:443 with SNI = host. Traefik fronts the
//     gateway with IngressRouteTCP HostSNI — speaking SOCKS5 on raw TCP
//     to :443 hangs until context deadline.
//  2. RFC 1928 SOCKS5 greet + RFC 1929 USERPASS sub-negotiation on top
//     of the *tls.Conn. User = workspace handle, Password = iog_ API key.
//  3. CONNECT linkedin.com:443. The destination TLS handshake is E2E on
//     the resulting byte stream — the proxy never sees plaintext.
//
// Graceful-skip contract: matches the Apollo client. If any of
// IOGRID_API_KEY / IOGRID_WORKSPACE / IOGRID_PROXY_URL is unset, the
// endpoint still returns 200 with empty fields and logs a one-line
// info — enrichment is always best-effort.
package enrich

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LinkedInClient fetches LinkedIn profile pages through the iogrid
// proxy and extracts the Result fields from the public SSR markup.
type LinkedInClient struct {
	APIKey    string
	Workspace string
	Proxy     string
	UserAgent string
	HTTP      *http.Client
}

// NewLinkedInClient wires a proxy-tunneled http.Client. Any empty
// config field yields a client whose Enrich is a no-op (matches the
// Apollo graceful-skip contract).
func NewLinkedInClient(apiKey, workspace, proxy string) *LinkedInClient {
	c := &LinkedInClient{
		APIKey:    apiKey,
		Workspace: workspace,
		Proxy:     proxy,
		UserAgent: "Mozilla/5.0 (compatible; vCardEnrich/0.1; +https://vcard.dynolabs.io/bot)",
	}
	if !c.Enabled() {
		return c
	}
	sni, _, err := net.SplitHostPort(proxy)
	if err != nil {
		slog.Warn("linkedin enrich: IOGRID_PROXY_URL must be host:port", "got", proxy, "err", err)
		c.Proxy = ""
		return c
	}
	c.HTTP = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialThroughIogrid(ctx, proxy, sni, workspace, apiKey, network, addr)
			},
			ForceAttemptHTTP2: false,
		},
	}
	return c
}

// LinkedInFromEnv reads IOGRID_API_KEY / IOGRID_WORKSPACE /
// IOGRID_PROXY_URL and constructs the canonical client.
// IOGRID_PROXY_URL defaults to "proxy.iogrid.org:443".
func LinkedInFromEnv() *LinkedInClient {
	proxy := os.Getenv("IOGRID_PROXY_URL")
	if proxy == "" {
		proxy = "proxy.iogrid.org:443"
	}
	return NewLinkedInClient(
		os.Getenv("IOGRID_API_KEY"),
		os.Getenv("IOGRID_WORKSPACE"),
		proxy,
	)
}

// Enabled reports whether every required field is populated. A
// disabled client returns empty results without contacting the proxy.
func (c *LinkedInClient) Enabled() bool {
	return c != nil && c.APIKey != "" && c.Workspace != "" && c.Proxy != ""
}

// EnrichByVanity GETs https://www.linkedin.com/in/<vanity> through the
// iogrid proxy and returns the parsed fields. Always returns nil error
// on transport / parse failures — enrichment is best-effort, matching
// Apollo.
func (c *LinkedInClient) EnrichByVanity(ctx context.Context, vanity string) (Result, error) {
	vanity = strings.TrimSpace(vanity)
	if vanity == "" {
		return Result{}, errors.New("vanity required")
	}
	if !c.Enabled() {
		slog.Info("linkedin enrich skipped: iogrid proxy not configured")
		return Result{}, nil
	}
	target := "https://www.linkedin.com/in/" + url.PathEscape(vanity)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		slog.Warn("linkedin enrich: build request failed", "err", err)
		return Result{}, nil
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	t0 := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		slog.Warn("linkedin enrich: proxy fetch failed",
			"vanity_redacted", redactVanity(vanity),
			"err", err)
		return Result{}, nil
	}
	defer resp.Body.Close()
	latency := time.Since(t0)

	if resp.StatusCode != http.StatusOK {
		slog.Info("linkedin enrich: non-200, returning empty",
			"status", resp.StatusCode,
			"vanity_redacted", redactVanity(vanity),
			"latency_ms", latency.Milliseconds())
		return Result{}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		slog.Warn("linkedin enrich: read body failed", "err", err)
		return Result{}, nil
	}
	out := ExtractLinkedInProfile(string(body))
	out.LinkedInURL = target
	slog.Info("linkedin enrich ok",
		"vanity_redacted", redactVanity(vanity),
		"has_title", out.Title != "",
		"has_company", out.Company != "",
		"has_photo", out.PhotoURL != "",
		"latency_ms", latency.Milliseconds())
	return out, nil
}

// ExtractLinkedInProfile parses LinkedIn's public-profile SSR markup.
// Exported so handlers + tests can hit it directly with fixture HTML.
//
// LinkedIn's canonical og:title shape is:
//
//	"Name - Title at Company - Company | LinkedIn"
//	"Name - Title at Company | LinkedIn"  (2-segment fallback)
//
// We split on " - ", strip the trailing " | LinkedIn", and treat the
// segments positionally. og:image yields the photo URL.
func ExtractLinkedInProfile(body string) Result {
	out := Result{}
	if m := ogTitleRe.FindStringSubmatch(body); len(m) >= 2 {
		title := decodeHTMLAttr(m[1])
		if i := strings.LastIndex(title, "|"); i > 0 {
			title = strings.TrimSpace(title[:i])
		}
		parts := strings.Split(title, " - ")
		if len(parts) >= 2 {
			out.Title = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 {
			out.Company = strings.TrimSpace(parts[2])
		}
	}
	if out.Company == "" && out.Title != "" {
		if i := strings.Index(strings.ToLower(out.Title), " at "); i > 0 {
			out.Company = strings.TrimSpace(out.Title[i+4:])
		}
	}
	if m := ogImageRe.FindStringSubmatch(body); len(m) >= 2 {
		out.PhotoURL = decodeHTMLAttr(m[1])
	}
	return out
}

var (
	ogTitleRe = regexp.MustCompile(`(?is)<meta[^>]+property\s*=\s*["']og:title["'][^>]*content\s*=\s*["']([^"']*)["']`)
	ogImageRe = regexp.MustCompile(`(?is)<meta[^>]+property\s*=\s*["']og:image["'][^>]*content\s*=\s*["']([^"']*)["']`)
)

func decodeHTMLAttr(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	return s
}

func redactVanity(v string) string {
	if len(v) <= 3 {
		return "***"
	}
	return v[:3] + "***"
}

func dialThroughIogrid(ctx context.Context, proxyHostPort, sni, user, pass, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("iogrid socks5: unsupported network %q", network)
	}
	d := &tls.Dialer{
		Config: &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS12,
		},
	}
	rawConn, err := d.DialContext(ctx, "tcp", proxyHostPort)
	if err != nil {
		return nil, fmt.Errorf("tls.Dial iogrid proxy: %w", err)
	}
	conn := rawConn.(*tls.Conn)
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := iogridSocks5Handshake(conn, user, pass, addr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func iogridSocks5Handshake(conn net.Conn, user, pass, addr string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fmt.Errorf("socks5 greet: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fmt.Errorf("socks5 read method select: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("socks5: bad version %#x in method-select reply", sel[0])
	}
	switch sel[1] {
	case 0x02:
	case 0xff:
		return errors.New("socks5: server rejected all offered auth methods (need USERPASS)")
	default:
		return fmt.Errorf("socks5: server selected method %#x, expected 0x02", sel[1])
	}

	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: username/password exceed 255 bytes (RFC 1929)")
	}
	req := make([]byte, 0, 3+len(user)+len(pass))
	req = append(req, 0x01)
	req = append(req, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 userpass write: %w", err)
	}
	var ar [2]byte
	if _, err := io.ReadFull(conn, ar[:]); err != nil {
		return fmt.Errorf("socks5 read userpass reply: %w", err)
	}
	if ar[0] != 0x01 {
		return fmt.Errorf("socks5: bad userpass version %#x", ar[0])
	}
	if ar[1] != 0x00 {
		return fmt.Errorf("socks5: authentication failed (status %#x)", ar[1])
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socks5: bad destination %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("socks5: bad destination port %q: %w", portStr, err)
	}
	creq := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			creq = append(creq, 0x01)
			creq = append(creq, v4...)
		} else {
			creq = append(creq, 0x04)
			creq = append(creq, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: hostname %q exceeds 255 bytes", host)
		}
		creq = append(creq, 0x03, byte(len(host)))
		creq = append(creq, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	creq = append(creq, pb[:]...)
	if _, err := conn.Write(creq); err != nil {
		return fmt.Errorf("socks5 CONNECT write: %w", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("socks5 CONNECT read header: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("socks5: bad CONNECT reply version %#x", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT rejected (REP=%s)", socks5RepName(hdr[1]))
	}
	switch hdr[3] {
	case 0x01:
		var skip [6]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return fmt.Errorf("socks5 CONNECT read bnd v4: %w", err)
		}
	case 0x04:
		var skip [18]byte
		if _, err := io.ReadFull(conn, skip[:]); err != nil {
			return fmt.Errorf("socks5 CONNECT read bnd v6: %w", err)
		}
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fmt.Errorf("socks5 CONNECT read bnd domain len: %w", err)
		}
		skip := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return fmt.Errorf("socks5 CONNECT read bnd domain: %w", err)
		}
	default:
		return fmt.Errorf("socks5: unexpected ATYP %#x", hdr[3])
	}
	return nil
}

func socks5RepName(b byte) string {
	switch b {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown(%#x)", b)
	}
}
