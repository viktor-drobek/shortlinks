package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestManageFormCSRFAndAssets(t *testing.T) {
	s, st := testServer(t)
	h := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", "/manage", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "name=\"csrf\"") {
		t.Fatalf("form=%d", w.Code)
	}
	for _, path := range []string{"/static/style.css", "/static/app.js"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, request("GET", path, ""))
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("asset=%s status=%d", path, w.Code)
		}
	}
	target := "https://example.org/call?jwt=a.b.c#config.callDisplayName=Test"
	post := func(body, origin string) *httptest.ResponseRecorder {
		r := request("POST", "/manage", body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	form := url.Values{"url": {target}, "title": {"<script>alert(1)</script>"}, "csrf": {s.csrf("alice")}}
	if w := post(form.Encode(), "https://evil.example"); w.Code != 403 {
		t.Fatalf("foreign Origin=%d", w.Code)
	}
	bad, err := url.ParseQuery(form.Encode())
	if err != nil {
		t.Fatal(err)
	}
	bad.Set("csrf", s.csrf("bob"))
	if w := post(bad.Encode(), "https://s.example"); w.Code != 403 {
		t.Fatalf("cross-user CSRF=%d", w.Code)
	}
	if w := post(form.Encode()+"&csrf=duplicate", "https://s.example"); w.Code != 400 {
		t.Fatalf("duplicate=%d", w.Code)
	}
	if w := post(form.Encode()+"&extra=unknown", "https://s.example"); w.Code != 400 {
		t.Fatalf("extra=%d", w.Code)
	}
	if w := post(form.Encode(), "https://s.example"); w.Code != 303 {
		t.Fatalf("create=%d %s", w.Code, w.Body.String())
	}
	ls, err := st.List(context.Background(), "alice", 100)
	if err != nil || len(ls) != 1 || ls[0].URL != target {
		t.Fatal("URL changed", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request("GET", "/manage", ""))
	if !strings.Contains(w.Body.String(), `action="/manage/`+ls[0].ID+`/delete"`) {
		t.Fatal("delete form must use the management route")
	}
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Fatal("title not escaped")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("HEAD", "/"+ls[0].Code, nil))
	if w.Code != 302 || w.Header().Get("Location") != target || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("redirect privacy")
	}
}

func TestBoundedLimiterAndProxyPeer(t *testing.T) {
	s, _ := testServer(t)
	now := s.c.Now()
	s.c.Now = func() time.Time { return now }
	r := httptest.NewRequest("GET", "/aBc123Xy", nil)
	r.Header.Set("X-Real-IP", "198.51.100.1")
	if got := clientIP(r); got != "198.51.100.1" {
		t.Fatal(got)
	}
	for i := 0; i < 120; i++ {
		if !s.allow("one") {
			t.Fatal("early limit")
		}
	}
	for i := 0; i < 10000; i++ {
		if s.allow("one") {
			t.Fatal("limit bypass")
		}
	}
	for i := 0; i < 5000; i++ {
		s.allow(fmt.Sprint(i))
	}
	if len(s.hits) > 4096 {
		t.Fatal("unbounded limiter")
	}
	now = now.Add(time.Minute)
	if !s.allow("new") {
		t.Fatal("expired entries not collected")
	}
}

func TestAPIRejectsMultipleJSONValuesAndExpiredLinks(t *testing.T) {
	s, st := testServer(t)
	for _, body := range []string{`{"url":"https://example.org"} {}`, `{"url":"https://example.org"} null`, `{"url":"https://example.org","unknown":true}`} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, request("POST", "/api/v1/links", body))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	expired := s.c.Now().Add(-time.Second)
	if _, err := st.Create(context.Background(), "alice", "one", "aBc123Xy", "https://example.org", "", &expired, "", nil); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/aBc123Xy", nil))
	if w.Code != 410 {
		t.Fatal(w.Code)
	}
}
