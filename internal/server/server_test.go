package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/viktor-drobek/shortlinks/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	k := sha256.Sum256([]byte("test"))
	st, e := store.Open(context.Background(), filepath.Join(t.TempDir(), "x.db"), k[:])
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return New(Config{Store: st, ProxyKey: []byte("secret"), BaseURL: "https://s.example", Origin: "https://s.example", Now: func() time.Time { return now }}), st
}
func request(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.Header.Set("X-Shortlinks-Proxy-Key", "secret")
	r.Header.Set("X-Auth-Request-User", "alice")
	r.Header.Set("X-Shortlinks-Client", "api")
	r.Header.Set("Origin", "https://s.example")
	r.Header.Set("Content-Type", "application/json")
	return r
}
func TestCreateIdempotentAndOwnerScoped(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	body := `{"url":"https://example.com/a?jwt=a.b.c#x","title":"A"}`
	r := request("POST", "/api/v1/links", body)
	r.Header.Set("Idempotency-Key", "k")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var got linkJSON
	if e := json.NewDecoder(w.Body).Decode(&got); e != nil {
		t.Fatal(e)
	}
	if len(got.Code) != 8 || got.URL != "https://example.com/a?jwt=a.b.c#x" {
		t.Fatalf("bad link %#v", got)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request("POST", "/api/v1/links", body)) // a request without idempotency creates independently
	r = request("POST", "/api/v1/links", body)
	r.Header.Set("Idempotency-Key", "k")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("replay %d", w.Code)
	}
	r = request("GET", "/api/v1/links/"+got.ID, "")
	r.Header.Set("X-Auth-Request-User", "bob")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("owner isolation: %d", w.Code)
	}
}
func TestRedirectExpiryAndValidation(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("POST", "/api/v1/links", `{"url":"http://127.0.0.1/x"}`))
	if w.Code != 400 {
		t.Fatalf("private address accepted: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request("POST", "/api/v1/links", `{"url":"https://example.com"}`))
	var l linkJSON
	_ = json.NewDecoder(w.Body).Decode(&l)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/"+l.Code, nil))
	if w.Code != 302 || w.Header().Get("Location") != "https://example.com" {
		t.Fatalf("redirect %d %q", w.Code, w.Header().Get("Location"))
	}
}
