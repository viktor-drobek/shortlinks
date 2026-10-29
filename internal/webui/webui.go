// Package webui holds the embedded management UI of shortlinks.
//
// The package exposes an fs.FS with the HTML template under
// templates/index.html and static assets under static/. The server builds
// its template with:
//
//	tpl, err := template.ParseFS(webui.FS, "templates/index.html")
//
// Page data is [PageData]; the link rows use the exported fields of
// [LinkRow], and the template renders times through the HTML-safe
// data methods on [LinkRow].
package webui

import (
	"embed"
	"io/fs"
	"time"
)

//go:embed templates static
var embedded embed.FS

// FS is the embedded UI file system: templates/ and static/.
var FS fs.FS = &embedded

// PageData is the data passed to the management page template.
type PageData struct {
	User    string
	BaseURL string
	CSRF    string
	Links   []LinkRow
	Error   string
	Notice  string
}

// LinkRow is one management row. Times are pointers because the underlying
// store rows may not have them set yet.
type LinkRow struct {
	ID            string
	Code          string
	ShortURL      string
	URL           string
	Title         string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	PendingSince  *time.Time
	LastCheckedAt *time.Time
	NextCheckAt   *time.Time
}

const ruLayout = "2006-01-02 15:04"

// Created returns the creation time for display.
func (l LinkRow) Created() string { return l.CreatedAt.Format(ruLayout) }

// Expires returns a human-readable expiry status, safe to render directly
// in the template: "бессрочно" for a permanent link, "до <date>" while it
// is still valid, and "истекла <date>" once it has lapsed.
func (l LinkRow) Expires() string {
	switch {
	case l.ExpiresAt == nil || l.ExpiresAt.IsZero():
		return "бессрочно"
	case l.ExpiresAt.After(time.Now().UTC()):
		return "до " + l.ExpiresAt.Format(ruLayout)
	default:
		return "истекла " + l.ExpiresAt.Format(ruLayout)
	}
}

// Pending returns a human-readable note while the link is awaiting
// deletion (after the first missed check), or "" when it is not pending.
func (l LinkRow) Pending() string {
	if l.PendingSince == nil || l.PendingSince.IsZero() {
		return ""
	}
	return "удаление после " + l.PendingSince.Format(ruLayout)
}
