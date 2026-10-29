package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/viktor-drobek/shortlinks/internal/store"
	"github.com/viktor-drobek/shortlinks/internal/webui"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

type Config struct {
	Store           *store.Store
	ProxyKey        []byte
	BaseURL, Origin string
	Now             func() time.Time
}
type Server struct {
	c    Config
	mu   sync.Mutex
	hits map[string]bucket
	tpl  *template.Template
}

func New(c Config) *Server {
	if c.Now == nil {
		c.Now = time.Now
	}
	tpl, err := template.ParseFS(webui.FS, "templates/index.html")
	if err != nil {
		panic(err)
	}
	return &Server{c: c, hits: map[string]bucket{}, tpl: tpl}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
	})
	m.HandleFunc("/api/v1/links", s.apiLinks)
	m.HandleFunc("/api/v1/links/", s.apiLink)
	m.HandleFunc("/manage", s.manage)
	m.HandleFunc("/manage/", s.manageDelete)
	staticFS, err := fs.Sub(webui.FS, "static")
	if err != nil {
		panic(err)
	}
	m.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	m.HandleFunc("/", s.redirect)
	return secure(m)
}
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) owner(r *http.Request) (string, bool) {
	u := r.Header.Get("X-Auth-Request-User")
	k := r.Header.Get("X-Shortlinks-Proxy-Key")
	if u == "" || len(u) > 256 || strings.ContainsAny(u, "|\r\n\x00") || len(k) != len(s.c.ProxyKey) || subtle.ConstantTimeCompare([]byte(k), s.c.ProxyKey) != 1 {
		return "", false
	}
	return u, true
}
func (s *Server) apiLinks(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.owner(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method == "GET" {
		ls, e := s.c.Store.List(r.Context(), owner, 100)
		if e != nil {
			fail(w, 500, "internal error")
			return
		}
		respond(w, 200, links(ls, s.c.BaseURL))
		return
	}
	if r.Method == http.MethodDelete {
		if r.Header.Get("X-Shortlinks-Client") != "api" || !originOK(r, s.c.Origin) {
			fail(w, 403, "forbidden")
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if !lowerHex64(key) {
			fail(w, 400, "invalid idempotency key")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		b, e := io.ReadAll(r.Body)
		if e != nil || len(b) != 0 {
			fail(w, 400, "DELETE body must be empty")
			return
		}
		if e = s.c.Store.RevokeKey(r.Context(), owner, key); e != nil {
			fail(w, 500, "internal error")
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST, DELETE")
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("X-Shortlinks-Client") != "api" || !originOK(r, s.c.Origin) {
		fail(w, 403, "forbidden")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "content type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	raw, e := io.ReadAll(r.Body)
	if e != nil {
		fail(w, 413, "payload too large")
		return
	}
	var in struct {
		URL       string     `json:"url"`
		Title     string     `json:"title"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e = d.Decode(&in); e != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, 400, "invalid JSON")
		return
	}
	if len(in.Title) > 256 || validateURL(in.URL) != nil {
		fail(w, 400, "invalid URL")
		return
	}
	if in.ExpiresAt != nil {
		t := in.ExpiresAt.UTC()
		in.ExpiresAt = &t
		if !t.After(s.c.Now().UTC()) {
			fail(w, 400, "expiry must be in the future")
			return
		}
	}
	idem := r.Header.Get("Idempotency-Key")
	if len(idem) > 128 {
		fail(w, 400, "idempotency key too long")
		return
	}
	code, e := code()
	if e != nil {
		fail(w, 500, "internal error")
		return
	}
	l, e := s.c.Store.Create(r.Context(), owner, uuid.NewString(), code, in.URL, in.Title, in.ExpiresAt, idem, store.BodyHash(raw))
	if errors.Is(e, store.ErrIdempotencyConflict) {
		fail(w, 409, "idempotency conflict")
		return
	}
	if e != nil {
		fail(w, 500, "internal error")
		return
	}
	respond(w, 201, link(l, s.c.BaseURL))
}
func lowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s *Server) apiLink(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.owner(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/links/")
	if id == "" || strings.Contains(id, "/") {
		fail(w, 404, "not found")
		return
	}
	if r.Method == "GET" {
		l, e := s.c.Store.Get(r.Context(), owner, id)
		if errors.Is(e, store.ErrNotFound) {
			fail(w, 404, "not found")
			return
		}
		if e != nil {
			fail(w, 500, "internal error")
			return
		}
		respond(w, 200, link(l, s.c.BaseURL))
		return
	}
	if r.Method == "DELETE" {
		if r.Header.Get("X-Shortlinks-Client") != "api" || !originOK(r, s.c.Origin) {
			fail(w, 403, "forbidden")
			return
		}
		e := s.c.Store.Revoke(r.Context(), owner, id)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			fail(w, 500, "internal error")
			return
		}
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Allow", "GET, DELETE")
	w.WriteHeader(405)
}
func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.owner(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		s.renderManage(w, r, owner, "", "")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.parseManageForm(w, r) {
		return
	}
	if r.Header.Get("Origin") != s.c.Origin || !s.validCSRF(owner, r.PostForm.Get("csrf")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if len(r.PostForm.Get("title")) > 256 || validateURL(r.PostForm.Get("url")) != nil {
		s.renderManage(w, r, owner, "Проверьте адрес ссылки.", "")
		return
	}
	var expires *time.Time
	if v := r.PostForm.Get("expires_at"); v != "" {
		t, e := time.ParseInLocation("2006-01-02 15:04", v, time.UTC)
		if e != nil || !t.After(s.c.Now().UTC()) {
			s.renderManage(w, r, owner, "Проверьте дату истечения.", "")
			return
		}
		expires = &t
	}
	c, e := code()
	if e != nil {
		s.renderManage(w, r, owner, "Не удалось создать ссылку.", "")
		return
	}
	if _, e = s.c.Store.Create(r.Context(), owner, uuid.NewString(), c, r.PostForm.Get("url"), r.PostForm.Get("title"), expires, "", nil); e != nil {
		s.renderManage(w, r, owner, "Не удалось создать ссылку.", "")
		return
	}
	http.Redirect(w, r, "/manage", http.StatusSeeOther)
}
func (s *Server) manageDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.owner(r)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if !s.parseManageForm(w, r) {
		return
	}
	if r.Header.Get("Origin") != s.c.Origin || !s.validCSRF(owner, r.PostForm.Get("csrf")) {
		http.Error(w, "forbidden", 403)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/manage/")
	if !strings.HasSuffix(p, "/delete") {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimSuffix(p, "/delete")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if e := s.c.Store.Revoke(r.Context(), owner, id); e != nil && !errors.Is(e, store.ErrNotFound) {
		http.Error(w, "internal error", 500)
		return
	}
	http.Redirect(w, r, "/manage", http.StatusSeeOther)
}
func (s *Server) renderManage(w http.ResponseWriter, r *http.Request, owner, errmsg, notice string) {
	ls, e := s.c.Store.List(r.Context(), owner, 100)
	if e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	rows := make([]webui.LinkRow, len(ls))
	for i, l := range ls {
		rows[i] = webui.LinkRow{ID: l.ID, Code: l.Code, ShortURL: strings.TrimSuffix(s.c.BaseURL, "/") + "/" + l.Code, URL: l.URL, Title: l.Title, CreatedAt: l.CreatedAt, ExpiresAt: l.ExpiresAt, PendingSince: l.PendingSince, LastCheckedAt: l.LastCheckedAt, NextCheckAt: l.NextCheckAt}
	}
	var b bytes.Buffer
	if e := s.tpl.ExecuteTemplate(&b, "manage", webui.PageData{User: owner, BaseURL: s.c.BaseURL, CSRF: s.csrf(owner), Links: rows, Error: errmsg, Notice: notice}); e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}
func (s *Server) parseManageForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "bad request", 400)
		return false
	}
	for k, v := range r.PostForm {
		if (k != "url" && k != "title" && k != "expires_at" && k != "csrf") || len(v) != 1 {
			http.Error(w, "bad request", 400)
			return false
		}
	}
	return true
}
func (s *Server) csrf(user string) string {
	ts := s.c.Now().UTC().Unix()
	m := hmac.New(sha256.New, s.c.ProxyKey)
	fmt := user + "|" + strconv.FormatInt(ts, 10)
	_, _ = m.Write([]byte(fmt))
	return base64.RawURLEncoding.EncodeToString([]byte(fmt + "|" + base64.RawURLEncoding.EncodeToString(m.Sum(nil))))
}
func (s *Server) validCSRF(user, tok string) bool {
	b, e := base64.RawURLEncoding.DecodeString(tok)
	if e != nil {
		return false
	}
	p := strings.Split(string(b), "|")
	if len(p) != 3 || p[0] != user {
		return false
	}
	ts, e := strconv.ParseInt(p[1], 10, 64)
	if e != nil || s.c.Now().UTC().Sub(time.Unix(ts, 0)) > 15*time.Minute || time.Unix(ts, 0).After(s.c.Now().Add(time.Minute)) {
		return false
	}
	m := hmac.New(sha256.New, s.c.ProxyKey)
	_, _ = m.Write([]byte(p[0] + "|" + p[1]))
	sig, e := base64.RawURLEncoding.DecodeString(p[2])
	return e == nil && hmac.Equal(sig, m.Sum(nil))
}
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(405)
		return
	}
	code := strings.TrimPrefix(r.URL.Path, "/")
	if len(code) != 8 || strings.Contains(code, "/") {
		http.NotFound(w, r)
		return
	}
	if !s.allow(clientIP(r)) {
		http.Error(w, "too many requests", 429)
		return
	}
	l, e := s.c.Store.Resolve(r.Context(), code)
	if errors.Is(e, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if e != nil {
		http.Error(w, "internal error", 500)
		return
	}
	if l.ExpiresAt != nil && !l.ExpiresAt.After(s.c.Now().UTC()) {
		w.WriteHeader(410)
		return
	}
	w.Header().Set("Location", l.URL)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(302)
}

type bucket struct {
	start time.Time
	count int
}

func clientIP(r *http.Request) string {
	// The backend is private. Caddy overwrites this header with the TCP peer IP.
	if ip, err := netip.ParseAddr(r.Header.Get("X-Real-IP")); err == nil {
		return ip.Unmap().String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) allow(remote string) bool {
	now := s.c.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, exists := s.hits[remote]
	if !exists && len(s.hits) >= 4096 {
		for key, old := range s.hits {
			if now.Sub(old.start) >= time.Minute {
				delete(s.hits, key)
			}
		}
		if len(s.hits) >= 4096 {
			return false
		}
	}
	if b.start.IsZero() || now.Sub(b.start) >= time.Minute {
		b = bucket{start: now}
	}
	if b.count >= 120 {
		return false
	}
	b.count++
	s.hits[remote] = b
	return true
}

func code() (string, error) {
	b := make([]byte, 8)
	for i := range b {
		for {
			var x [1]byte
			if _, e := rand.Read(x[:]); e != nil {
				return "", e
			}
			if x[0] < 248 {
				b[i] = alphabet[int(x[0])%62]
				break
			}
		}
	}
	return string(b), nil
}
func validateURL(raw string) error {
	if strings.ContainsAny(raw, "\r\n") {
		return errors.New("line break")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("bad url")
	}
	h := u.Hostname()
	lowerHost := strings.ToLower(h)
	if strings.HasSuffix(lowerHost, ".internal") || strings.HasSuffix(lowerHost, ".local") || strings.EqualFold(lowerHost, "localhost") {
		return errors.New("private host")
	}
	if a, e := netip.ParseAddr(h); e == nil && !a.IsGlobalUnicast() {
		return errors.New("private ip")
	}
	if a, e := netip.ParseAddr(h); e == nil {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalMulticast() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
			return errors.New("private ip")
		}
	}
	return nil
}
func originOK(r *http.Request, origin string) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == origin
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

type linkJSON struct {
	ID            string     `json:"id"`
	Code          string     `json:"code"`
	ShortURL      string     `json:"short_url"`
	URL           string     `json:"url"`
	Title         string     `json:"title"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	PendingSince  *time.Time `json:"pending_since"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	NextCheckAt   *time.Time `json:"next_check_at"`
}

func link(l store.Link, base string) linkJSON {
	return linkJSON{ID: l.ID, Code: l.Code, ShortURL: strings.TrimSuffix(base, "/") + "/" + l.Code, URL: l.URL, Title: l.Title, CreatedAt: l.CreatedAt, ExpiresAt: l.ExpiresAt, PendingSince: l.PendingSince, LastCheckedAt: l.LastCheckedAt, NextCheckAt: l.NextCheckAt}
}
func links(ls []store.Link, b string) []linkJSON {
	o := make([]linkJSON, len(ls))
	for i, l := range ls {
		o[i] = link(l, b)
	}
	return o
}
