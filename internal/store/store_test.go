package store

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func TestTwoPhaseMissingDeletion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	k := sha256.Sum256([]byte("key"))
	s, e := Open(context.Background(), filepath.Join(t.TempDir(), "x.db"), k[:])
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.now = func() time.Time { return now }
	l, e := s.Create(context.Background(), "u", "id", "aBc123Xy", "https://example.com", "", nil, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(7 * 24 * time.Hour)
	due, e := s.Due(context.Background(), 1, time.Minute)
	if e != nil || len(due) != 1 {
		t.Fatalf("due %#v %v", due, e)
	}
	if e = s.Complete(context.Background(), due[0], "missing"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Resolve(context.Background(), l.Code); e != nil {
		t.Fatal(e)
	}
	now = now.Add(7 * 24 * time.Hour)
	due, e = s.Due(context.Background(), 1, time.Minute)
	if e != nil || len(due) != 1 {
		t.Fatalf("second due %#v %v", due, e)
	}
	if e = s.Complete(context.Background(), due[0], "missing"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Resolve(context.Background(), l.Code); e != ErrNotFound {
		t.Fatalf("want revoked, got %v", e)
	}
}
