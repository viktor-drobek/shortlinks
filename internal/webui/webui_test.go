package webui

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
	"time"
)

// TestParseFS verifies the management template parses from the embedded FS
// the same way the server wires it, and that a populated page renders the
// expected structure without panicking.
func TestParseFS(t *testing.T) {
	tpl, err := template.ParseFS(FS, "templates/index.html")
	if err != nil {
		t.Fatalf("ParseFS: %v", err)
	}

	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, "manage", PageData{
		User:    "example",
		BaseURL: "https://s.2050.su",
		CSRF:    "csrf-token",
		Links: []LinkRow{{
			ID:        "11111111-1111-1111-1111-111111111111",
			Code:      "Ab1CdEf0",
			ShortURL:  "https://s.2050.su/Ab1CdEf0",
			URL:       "https://example.com/path?x=1#frag",
			Title:     "Тест",
			CreatedAt: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
			ExpiresAt: ptrTime(time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC)),
		}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"https://s.2050.su/Ab1CdEf0",
		"Тест",
		"https://example.com/path?x=1#frag",
		`name="csrf" value="csrf-token"`,
		"2026-12-31 23:59",
		"Истекает",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}

	// The page must not contain inline script or style, per the CSP policy.
	// No inline script or style attributes: every script/style is a
	// reference to a static file.
	if strings.Contains(out, "onsubmit=") || strings.Contains(out, "onclick=") {
		t.Error("rendered page contains an inline event handler")
	}
	if !strings.Contains(out, `src="/static/app.js"`) {
		t.Error("rendered page does not reference /static/app.js")
	}
	// It must reference the external stylesheet exactly.
	if !strings.Contains(out, `href="/static/style.css"`) {
		t.Error("rendered page does not reference /static/style.css")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
