package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeyedDeleteTombstonesOwnerKey(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	key := strings.Repeat("a", 64)
	del := request(http.MethodDelete, "/api/v1/links", "")
	del.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, del)
	if w.Code != 204 {
		t.Fatalf("delete-before-create=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, del)
	if w.Code != 204 {
		t.Fatalf("repeat delete=%d", w.Code)
	}
	post := request(http.MethodPost, "/api/v1/links", `{"url":"https://example.com"}`)
	post.Header.Set("Idempotency-Key", key)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if w.Code != 409 {
		t.Fatalf("tombstoned create=%d", w.Code)
	}
	post = request(http.MethodPost, "/api/v1/links", `{"url":"https://example.com"}`)
	post.Header.Set("Idempotency-Key", key)
	post.Header.Set("X-Auth-Request-User", "bob")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if w.Code != 201 {
		t.Fatalf("other owner=%d", w.Code)
	}
}
func TestKeyedDeleteValidation(t *testing.T) {
	s, _ := testServer(t)
	h := s.Handler()
	r := request(http.MethodDelete, "/api/v1/links", "x")
	r.Header.Set("Idempotency-Key", "bad")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("want 400 got %d", w.Code)
	}
}
