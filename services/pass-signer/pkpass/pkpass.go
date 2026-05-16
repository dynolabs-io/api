// Package pkpass builds and signs Apple Wallet .pkpass files.
//
// A .pkpass is a ZIP containing:
//   - pass.json         — pass metadata + visual fields
//   - manifest.json     — SHA-1 of every other file in the bundle
//   - signature         — PKCS#7 detached CMS signature of manifest.json
//   - icon.png / logo.png / etc — display assets at @1x / @2x / @3x
//
// Apple Wallet validates the signature against the Apple Root CA via the
// WWDR intermediate cert. We embed WWDR in the signature so iOS doesn't
// need to fetch it.
package pkpass

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"

	"go.mozilla.org/pkcs7"
)

type Signer struct {
	PassCert *x509.Certificate
	PassKey  *rsa.PrivateKey
	WWDR     *x509.Certificate
}

// LoadSigner reads PEM-encoded cert + key + WWDR intermediate from disk.
func LoadSigner(certPEM, keyPEM, wwdrPEM []byte) (*Signer, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("pass cert: %w", err)
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pass key: %w", err)
	}
	wwdr, err := parseCertPEM(wwdrPEM)
	if err != nil {
		return nil, fmt.Errorf("wwdr: %w", err)
	}
	return &Signer{PassCert: cert, PassKey: key, WWDR: wwdr}, nil
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no CERTIFICATE block")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
}

func parseKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PRIVATE KEY block")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := any.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an RSA key")
			}
			return rsaKey, nil
		}
		data = rest
	}
}

// Pass is the structured metadata that becomes pass.json.
type Pass struct {
	FormatVersion      int       `json:"formatVersion"`
	PassTypeIdentifier string    `json:"passTypeIdentifier"`
	SerialNumber       string    `json:"serialNumber"`
	TeamIdentifier     string    `json:"teamIdentifier"`
	OrganizationName   string    `json:"organizationName"`
	Description        string    `json:"description"`
	LogoText           string    `json:"logoText,omitempty"`
	ForegroundColor    string    `json:"foregroundColor,omitempty"`
	BackgroundColor    string    `json:"backgroundColor,omitempty"`
	LabelColor         string    `json:"labelColor,omitempty"`
	// Web-service URL + auth token: enables Wallet to call back for
	// push-driven pass updates. Wallet will POST to
	// <webServiceURL>/v1/devices/.../registrations/... when the user
	// adds the pass, then GET /v1/passes/... when notified.
	WebServiceURL       string    `json:"webServiceURL,omitempty"`
	AuthenticationToken string    `json:"authenticationToken,omitempty"`
	Barcodes           []Barcode `json:"barcodes,omitempty"`
	// One of Generic / StoreCard / Coupon / EventTicket / BoardingPass.
	// EventTicket has the most prominent center-of-pass barcode area —
	// much larger than Generic or StoreCard which keep the barcode small.
	Generic     *Style       `json:"generic,omitempty"`
	StoreCard   *Style       `json:"storeCard,omitempty"`
	EventTicket *Style       `json:"eventTicket,omitempty"`
	Coupon      *Style       `json:"coupon,omitempty"`
	BoardingPass *BoardingPassStyle `json:"boardingPass,omitempty"`

	// iOS 18+ enhanced event ticket layout. When set to
	// ["posterEventTicket", "eventTicket"], iOS 18+ renders the new
	// full-bleed artwork layout (Nene Royal style), older iOS falls
	// back to the legacy eventTicket layout. Requires artwork.png /
	// primaryLogo.png / secondaryLogo.png assets in the bundle.
	PreferredStyleSchemes []string `json:"preferredStyleSchemes,omitempty"`

	// Semantic tags needed for posterEventTicket to render correctly.
	// Apple requires at least an event start date for the new layout.
	Semantics map[string]any `json:"semantics,omitempty"`
}

type Barcode struct {
	Format          string `json:"format"`           // PKBarcodeFormatQR
	Message         string `json:"message"`
	MessageEncoding string `json:"messageEncoding"`  // iso-8859-1 / utf-8
	AltText         string `json:"altText,omitempty"`
}

// Style is shared by Generic / StoreCard / etc — same field set.
type Style struct {
	HeaderFields    []Field `json:"headerFields,omitempty"`
	PrimaryFields   []Field `json:"primaryFields,omitempty"`
	SecondaryFields []Field `json:"secondaryFields,omitempty"`
	AuxiliaryFields []Field `json:"auxiliaryFields,omitempty"`
	BackFields      []Field `json:"backFields,omitempty"`
}

// Generic is kept as an alias for backwards compat with callers that
// still type pkpass.Generic{...}.
type Generic = Style

// BoardingPassStyle adds the mandatory transitType field on top of the
// regular Style. Without transitType, Apple Wallet rejects the pass.
// Valid values: PKTransitTypeAir, PKTransitTypeBoat, PKTransitTypeBus,
// PKTransitTypeGeneric, PKTransitTypeTrain. The transit type doesn't
// change the visual layout meaningfully — it just shows a small icon.
type BoardingPassStyle struct {
	TransitType     string  `json:"transitType"`
	HeaderFields    []Field `json:"headerFields,omitempty"`
	PrimaryFields   []Field `json:"primaryFields,omitempty"`
	SecondaryFields []Field `json:"secondaryFields,omitempty"`
	AuxiliaryFields []Field `json:"auxiliaryFields,omitempty"`
	BackFields      []Field `json:"backFields,omitempty"`
}

type Field struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
}

// Build creates a signed .pkpass binary from the pass metadata + asset map.
// `assets` is a map of filename → bytes (e.g. {"icon.png": ..., "icon@2x.png": ...}).
// At minimum, "icon.png" and "icon@2x.png" are REQUIRED by iOS.
func (s *Signer) Build(pass Pass, assets map[string][]byte) ([]byte, error) {
	if _, ok := assets["icon.png"]; !ok {
		return nil, fmt.Errorf("missing required asset: icon.png")
	}
	passJSON, err := json.Marshal(pass)
	if err != nil {
		return nil, fmt.Errorf("marshal pass.json: %w", err)
	}

	files := map[string][]byte{}
	files["pass.json"] = passJSON
	for name, data := range assets {
		files[name] = data
	}

	// manifest.json maps filename → SHA-1 hex of that file's bytes.
	manifest := map[string]string{}
	for name, data := range files {
		h := sha1.Sum(data)
		manifest[name] = fmt.Sprintf("%x", h)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	files["manifest.json"] = manifestJSON

	// PKCS#7 detached signature over manifest.json.
	signedData, err := pkcs7.NewSignedData(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("new signed data: %w", err)
	}
	signedData.AddCertificate(s.WWDR)
	if err := signedData.AddSigner(s.PassCert, s.PassKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("add signer: %w", err)
	}
	signedData.Detach()
	signature, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish signature: %w", err)
	}
	files["signature"] = signature

	// ZIP the bundle.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		fw, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(fw, bytes.NewReader(data)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
