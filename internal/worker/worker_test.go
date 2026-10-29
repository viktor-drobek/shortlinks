package worker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/viktor-drobek/shortlinks/internal/store"
)

func TestPersistedScheduleAndUnknownVerdict(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "links.db")
	key := sha256.Sum256([]byte("fixture-key"))
	st, err := store.Open(ctx, path, key[:])
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	link, err := st.Create(ctx, "alice", "one", "aBc123Xy", "https://example.org", "", nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	w := Worker{Store: st, Check: func(context.Context, string) string { calls++; return "unrecognized" }}
	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("checked before weekly due time")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE links SET next_check_at=1"); err != nil {
		t.Fatal(err)
	}
	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "alice", link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got.PendingSince != nil || got.LastCheckedAt == nil || got.NextCheckAt == nil || time.Until(*got.NextCheckAt) < 6*24*time.Hour {
		t.Fatal("unknown verdict changed deletion state or schedule")
	}
	if err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("schedule lost between passes")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	done := make(chan struct{})
	go func() { w.Run(canceled); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker ignored shutdown")
	}
}
