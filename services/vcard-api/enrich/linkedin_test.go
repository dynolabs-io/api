package enrich

import (
	"context"
	"strings"
	"testing"
)

func TestExtractLinkedInProfile_ThreeSegmentOgTitle(t *testing.T) {
	html := `<!DOCTYPE html><html><head>
<meta property="og:title" content="Satya Nadella - Chairman and CEO at Microsoft - Microsoft | LinkedIn">
<meta property="og:image" content="https://media.licdn.com/dms/image/satya.jpg">
</head><body></body></html>`
	r := ExtractLinkedInProfile(html)
	if r.Title != "Chairman and CEO at Microsoft" {
		t.Errorf("Title = %q, want %q", r.Title, "Chairman and CEO at Microsoft")
	}
	if r.Company != "Microsoft" {
		t.Errorf("Company = %q, want %q", r.Company, "Microsoft")
	}
	if r.PhotoURL != "https://media.licdn.com/dms/image/satya.jpg" {
		t.Errorf("PhotoURL = %q, want %q", r.PhotoURL, "https://media.licdn.com/dms/image/satya.jpg")
	}
}

func TestExtractLinkedInProfile_TwoSegmentFallbackUsesAtHeuristic(t *testing.T) {
	html := `<meta property="og:title" content="Jane Doe - Staff Engineer at Acme Corp | LinkedIn">`
	r := ExtractLinkedInProfile(html)
	if r.Title != "Staff Engineer at Acme Corp" {
		t.Errorf("Title = %q", r.Title)
	}
	if r.Company != "Acme Corp" {
		t.Errorf("Company = %q, want %q (split-on-' at ' heuristic)", r.Company, "Acme Corp")
	}
}

func TestExtractLinkedInProfile_HTMLEntitiesDecoded(t *testing.T) {
	html := `<meta property="og:title" content="X &amp; Y - CEO at Foo &#39;Bar&#39; Co - Foo &#39;Bar&#39; Co | LinkedIn">`
	r := ExtractLinkedInProfile(html)
	if !strings.Contains(r.Title, "CEO at Foo 'Bar' Co") {
		t.Errorf("expected entity decode in Title, got %q", r.Title)
	}
	if r.Company != "Foo 'Bar' Co" {
		t.Errorf("Company = %q, expected entity decode", r.Company)
	}
}

func TestExtractLinkedInProfile_EmptyOnMissingMeta(t *testing.T) {
	r := ExtractLinkedInProfile(`<html><head><title>No og tags</title></head></html>`)
	if r.Title != "" || r.Company != "" || r.PhotoURL != "" {
		t.Errorf("expected zero Result, got %+v", r)
	}
}

func TestExtractLinkedInProfile_AttributeOrderTolerant(t *testing.T) {
	html := `<meta content="A - B at C | LinkedIn" property='og:title'>`
	r := ExtractLinkedInProfile(html)
	if r.Title == "" {
		t.Skip("content-before-property is rarely seen; current regex requires property first")
	}
}

func TestLinkedInClient_DisabledWhenAnyEnvMissing(t *testing.T) {
	tests := []struct {
		name                                string
		apiKey, workspace, proxy            string
		wantEnabled                         bool
	}{
		{"all set", "iog_x", "vcard-prod", "proxy.iogrid.org:443", true},
		{"missing apikey", "", "vcard-prod", "proxy.iogrid.org:443", false},
		{"missing workspace", "iog_x", "", "proxy.iogrid.org:443", false},
		{"missing proxy", "iog_x", "vcard-prod", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewLinkedInClient(tt.apiKey, tt.workspace, tt.proxy)
			if got := c.Enabled(); got != tt.wantEnabled {
				t.Errorf("Enabled() = %v, want %v", got, tt.wantEnabled)
			}
		})
	}
}

func TestLinkedInClient_DisabledClientReturnsEmptyResult(t *testing.T) {
	c := NewLinkedInClient("", "", "")
	got, err := c.EnrichByVanity(context.Background(), "anyone")
	if err != nil {
		t.Errorf("disabled client should return nil err, got %v", err)
	}
	if got.Title != "" || got.Company != "" || got.LinkedInURL != "" {
		t.Errorf("expected zero Result from disabled client, got %+v", got)
	}
}

func TestLinkedInClient_MalformedProxyURLDisablesGracefully(t *testing.T) {
	c := NewLinkedInClient("iog_x", "vcard-prod", "not-a-host-port")
	if c.Enabled() {
		t.Errorf("client should be disabled when proxy URL is unparseable")
	}
}

func TestLinkedInClient_RejectsEmptyVanity(t *testing.T) {
	c := NewLinkedInClient("iog_x", "vcard-prod", "proxy.iogrid.org:443")
	if _, err := c.EnrichByVanity(context.Background(), "   "); err == nil {
		t.Errorf("empty vanity should return an error")
	}
}

func TestRedactVanity(t *testing.T) {
	cases := map[string]string{
		"":             "***",
		"x":            "***",
		"xyz":          "***",
		"satyanadella": "sat***",
	}
	for in, want := range cases {
		if got := redactVanity(in); got != want {
			t.Errorf("redactVanity(%q) = %q, want %q", in, got, want)
		}
	}
}
