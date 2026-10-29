package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevokedIdempotentReplay(t *testing.T) {
	for _, mode := range []string{"owner-delete", "checker-delete"} {
		t.Run(mode, func(t *testing.T) {
			s, st := testServer(t)
			h := s.Handler()
			const key = "revoked-replay-key"
			const body = `{"url":"https://example.com/?jwt=synthetic","title":"Fixture"}`
			post := request(http.MethodPost, "/api/v1/links", body)
			post.Header.Set("Idempotency-Key", key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, post)
			if w.Code != http.StatusCreated {
				t.Fatalf("create status=%d", w.Code)
			}
			var link linkJSON
			if err := json.Unmarshal(w.Body.Bytes(), &link); err != nil {
				t.Fatal(err)
			}
			if mode == "owner-delete" {
				w = httptest.NewRecorder()
				h.ServeHTTP(w, request(http.MethodDelete, "/api/v1/links/"+link.ID, ""))
				if w.Code != http.StatusNoContent {
					t.Fatalf("delete status=%d", w.Code)
				}
			} else {
				ctx := context.Background()
				record, err := st.Get(ctx, "alice", link.ID)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.RevokeSystem(ctx, record.ID, record.Revision); err != nil {
					t.Fatal(err)
				}
			}
			for _, replayBody := range []string{body, `{"url":"https://example.com/changed"}`} {
				post = request(http.MethodPost, "/api/v1/links", replayBody)
				post.Header.Set("Idempotency-Key", key)
				w = httptest.NewRecorder()
				h.ServeHTTP(w, post)
				if w.Code != http.StatusConflict {
					t.Fatalf("revoked replay status=%d, want 409", w.Code)
				}
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+link.Code, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("revoked redirect status=%d", w.Code)
			}
		})
	}
}
