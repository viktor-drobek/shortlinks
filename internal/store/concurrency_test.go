package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	k := sha256.Sum256([]byte("fixture-key"))
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "links.db"), k[:])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestConcurrentIdempotencyOneWinner(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := s.Create(ctx, "alice", fmt.Sprint(i), fmt.Sprintf("xY%06d", i), "https://example.org/a", "", nil, "one", BodyHash([]byte("same")))
			if err != nil {
				t.Error(err)
				return
			}
			ids <- l.ID
		}(i)
	}
	wg.Wait()
	close(ids)
	var first string
	for id := range ids {
		if first == "" {
			first = id
		}
		if first != id {
			t.Fatal("idempotency produced multiple links")
		}
	}
	ls, err := s.List(ctx, "alice", 100)
	if err != nil || len(ls) != 1 {
		t.Fatalf("count=%d err=%v", len(ls), err)
	}
	var fk int
	if err := s.db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatal("foreign_keys disabled", err)
	}
}

func TestCheckerUncertainRecoveryAndStaleResult(t *testing.T) {
	s, now := testStore(t)
	ctx := context.Background()
	l, err := s.Create(ctx, "alice", "one", "aBc123Xy", "https://example.org", "", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(verdict string) Link {
		t.Helper()
		*now = now.Add(7 * 24 * time.Hour)
		due, err := s.Due(ctx, 1, time.Minute)
		if err != nil || len(due) != 1 {
			t.Fatalf("due=%d err=%v", len(due), err)
		}
		if err := s.Complete(ctx, due[0], verdict); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "alice", l.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := check("missing"); got.PendingSince == nil {
		t.Fatal("not marked")
	}
	if got := check("uncertain"); got.PendingSince == nil {
		t.Fatal("uncertain removed mark")
	}
	if got := check("healthy"); got.PendingSince != nil {
		t.Fatal("recovery retained mark")
	}
	*now = now.Add(7 * 24 * time.Hour)
	due, err := s.Due(ctx, 1, time.Minute)
	if err != nil || len(due) != 1 {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "alice", l.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, due[0], "healthy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve(ctx, l.Code); err != ErrNotFound {
		t.Fatal("stale result resurrected link", err)
	}
}

func TestLeaseRecoveryAndEncryptionKeyMismatch(t *testing.T) {
	s, now := testStore(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, "alice", "one", "aBc123Xy", "https://example.org/?jwt=fixture", "", nil, "", nil); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(7 * 24 * time.Hour)
	first, err := s.Due(ctx, 1, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatal("first lease", err)
	}
	second, err := s.Due(ctx, 1, time.Minute)
	if err != nil || len(second) != 0 {
		t.Fatal("duplicate lease", err)
	}
	*now = now.Add(2 * time.Minute)
	recovered, err := s.Due(ctx, 1, time.Minute)
	if err != nil || len(recovered) != 1 {
		t.Fatal("expired lease", err)
	}
	if err := s.Complete(ctx, first[0], "missing"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "alice", "one")
	if err != nil || got.PendingSince != nil {
		t.Fatal("stale lease changed state", err)
	}
	var encrypted []byte
	if err := s.db.QueryRow("SELECT target FROM links").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	bad := sha256.Sum256([]byte("wrong"))
	other, err := Open(ctx, filepath.Join(t.TempDir(), "other.db"), bad[:])
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.decrypt(encrypted); err == nil {
		t.Fatal("wrong key accepted")
	}
}
