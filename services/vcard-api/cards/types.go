// Package cards defines the Card domain type and its persistence + HTTP
// handlers. Mirrors the mobile-side lib/types.ts so server and client share
// the same JSON shape.
package cards

import "time"

type Social struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

type Card struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Label       string    `json:"label"`
	Name        string    `json:"name"`
	Title       string    `json:"title,omitempty"`
	Company     string    `json:"company,omitempty"`
	Emails      []string  `json:"emails"`
	Phones      []string  `json:"phones"`
	Socials     []Social  `json:"socials"`
	PhotoURL     string `json:"photoUrl,omitempty"`
	BrandLogoURL string `json:"brandLogoUrl,omitempty"` // company/brand mark, separate from face photo
	Template     string `json:"template"`
	CustomColor  string `json:"customColor,omitempty"`
	WalletStyle  string `json:"walletStyle,omitempty"`
	DeviceID    string    `json:"deviceId,omitempty"`
	UserID      string    `json:"userId,omitempty"` // set when the card is attached to a signed-in user
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
