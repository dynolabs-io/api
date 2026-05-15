// Package auth — Sign in with Apple verification, plus issuance of our
// own HS256 session token.
//
// Flow:
//
//	Mobile SIWA → identityToken (Apple's signed JWT)
//	  ↓ POST /v1/auth/apple
//	Server verifies identityToken vs Apple's JWKS, upserts the user
//	keyed by Apple's stable `sub`, issues our own HS256 JWT containing
//	the user_id claim.
//	  ↓
//	Mobile stores our token in Keychain, sends as Authorization: Bearer.
//	Per-request: server HMAC-verifies the token (fast, no network).
//
// We don't store Apple's identity token — once we've issued our own
// token, Apple's expiry is irrelevant.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	appleIssuer = "https://appleid.apple.com"
	appleJWKS   = "https://appleid.apple.com/auth/keys"
)

// AppleClaims is the subset of Apple identity-token claims we use.
type AppleClaims struct {
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

// SessionClaims is what we encode into our own HS256 token.
type SessionClaims struct {
	UserID string `json:"uid"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

// Verifier holds the cached Apple JWKS and our HMAC secret.
type Verifier struct {
	BundleID    string
	HMACSecret  []byte
	HTTPClient  *http.Client
	SessionTTL  time.Duration
	keysMu      sync.RWMutex
	keys        map[string]*ecdsa.PublicKey
	keysFetched time.Time
}

// New constructs a Verifier. bundleID must match the audience claim in
// Apple identity tokens (the mobile app's bundle identifier). secret is
// the HMAC key used to sign our own session tokens — must be at least
// 32 bytes and stay stable across deploys.
func New(bundleID string, secret []byte) *Verifier {
	return &Verifier{
		BundleID:   bundleID,
		HMACSecret: secret,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		SessionTTL: 365 * 24 * time.Hour, // long-lived; mobile can re-auth via SIWA whenever
	}
}

// VerifyAppleIdentityToken parses and cryptographically verifies an
// identity token issued by Apple at SIWA completion. On success returns
// the parsed claims (caller upserts the user keyed by claims.Sub).
func (v *Verifier) VerifyAppleIdentityToken(ctx context.Context, tok string) (*AppleClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerB, &hdr); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}
	if hdr.Alg != "ES256" {
		return nil, fmt.Errorf("unexpected alg %q (want ES256)", hdr.Alg)
	}

	pub, err := v.appleKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("sig decode: %w", err)
	}
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("sig length %d (want 64 for ES256)", len(sigBytes))
	}
	rInt := new(big.Int).SetBytes(sigBytes[:32])
	sInt := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(pub, digest[:], rInt, sInt) {
		return nil, errors.New("signature mismatch")
	}

	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var claims AppleClaims
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}
	if claims.Iss != appleIssuer {
		return nil, fmt.Errorf("issuer %q (want %s)", claims.Iss, appleIssuer)
	}
	if v.BundleID != "" && claims.Aud != v.BundleID {
		return nil, fmt.Errorf("audience %q (want %s)", claims.Aud, v.BundleID)
	}
	now := time.Now().Unix()
	if claims.Exp != 0 && now > claims.Exp {
		return nil, fmt.Errorf("token expired %ds ago", now-claims.Exp)
	}
	if claims.Sub == "" {
		return nil, errors.New("missing sub")
	}
	return &claims, nil
}

// IssueSession returns a signed HS256 JWT for the given user id.
func (v *Verifier) IssueSession(userID string) (string, error) {
	now := time.Now()
	claims := SessionClaims{
		UserID: userID,
		Iat:    now.Unix(),
		Exp:    now.Add(v.SessionTTL).Unix(),
	}
	header := `{"alg":"HS256","typ":"JWT"}`
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, v.HMACSecret)
	mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sigB64, nil
}

// VerifySession parses and verifies one of OUR session tokens.
func (v *Verifier) VerifySession(tok string) (*SessionClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed session token")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, v.HMACSecret)
	mac.Write([]byte(signingInput))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("session signature mismatch")
	}
	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("session payload decode: %w", err)
	}
	var claims SessionClaims
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, fmt.Errorf("session payload parse: %w", err)
	}
	if claims.Exp != 0 && time.Now().Unix() > claims.Exp {
		return nil, errors.New("session expired")
	}
	if claims.UserID == "" {
		return nil, errors.New("missing uid")
	}
	return &claims, nil
}

// appleKey returns the cached Apple public key for the given kid, refreshing
// the JWKS from Apple if needed. Apple rotates keys ~yearly so a 24h cache
// is fine.
func (v *Verifier) appleKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.keysMu.RLock()
	k, ok := v.keys[kid]
	fresh := time.Since(v.keysFetched) < 24*time.Hour
	v.keysMu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	k, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return k, nil
}

func (v *Verifier) refreshJWKS(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", appleJWKS, nil)
	res, err := v.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("apple jwks fetch: %w", err)
	}
	defer res.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return fmt.Errorf("apple jwks parse: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, jk := range set.Keys {
		if jk.Kty != "EC" || jk.Crv != "P-256" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(jk.X)
		if err != nil {
			continue
		}
		y, err := base64.RawURLEncoding.DecodeString(jk.Y)
		if err != nil {
			continue
		}
		out[jk.Kid] = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	}
	if len(out) == 0 {
		return errors.New("apple jwks empty")
	}
	v.keysMu.Lock()
	v.keys = out
	v.keysFetched = time.Now()
	v.keysMu.Unlock()
	return nil
}
