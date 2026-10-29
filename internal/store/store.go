package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("link not found")
var ErrIdempotencyConflict = errors.New("idempotency key used with a different request")

type Link struct {
	ID, Code, ShortURL, URL, Title                      string
	CreatedAt                                           time.Time
	ExpiresAt, PendingSince, LastCheckedAt, NextCheckAt *time.Time
	Revision                                            int64
}
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	now  func() time.Time
}

func Open(ctx context.Context, path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// A single connection keeps PRAGMAs effective and serializes SQLite writers.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, aead: g, now: time.Now}
	_, err = db.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS links (id TEXT PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, code TEXT NOT NULL, owner TEXT NOT NULL, target BLOB NOT NULL, title TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, pending_since INTEGER, last_checked_at INTEGER, next_check_at INTEGER NOT NULL, lease_until INTEGER, revision INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER);
 CREATE INDEX IF NOT EXISTS links_due ON links(next_check_at, lease_until);
 CREATE TABLE IF NOT EXISTS retired_codes (code_hash BLOB PRIMARY KEY, retired_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS idempotency (owner TEXT NOT NULL, key TEXT NOT NULL, body_hash BLOB NOT NULL, link_id TEXT NOT NULL, PRIMARY KEY(owner,key), FOREIGN KEY(link_id) REFERENCES links(id));`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	// Validate an existing encrypted value before returning a usable store. This
	// makes a wrong key an open failure rather than a later checker failure.
	var target []byte
	err = db.QueryRowContext(ctx, "SELECT target FROM links WHERE length(target)>0 LIMIT 1").Scan(&target)
	if err == nil {
		if _, err = s.decrypt(target); err != nil {
			_ = db.Close()
			return nil, errors.New("cannot decrypt existing database with supplied key")
		}
	} else if err != sql.ErrNoRows {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) encrypt(v string) ([]byte, error) {
	n := make([]byte, s.aead.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return append(n, s.aead.Seal(nil, n, []byte(v), nil)...), nil
}
func (s *Store) decrypt(v []byte) (string, error) {
	if len(v) < s.aead.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	n := v[:s.aead.NonceSize()]
	p, e := s.aead.Open(nil, n, v[s.aead.NonceSize():], nil)
	return string(p), e
}
func codeHash(code string) []byte { h := sha256.Sum256([]byte(code)); return h[:] }
func ns(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().UnixNano()
}
func ptr(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(0, n.Int64).UTC()
	return &t
}
func scan(row interface{ Scan(...any) error }, s *Store) (Link, error) {
	var l Link
	var target []byte
	var cr int64
	var ex, pe, la, nx sql.NullInt64
	var rev int64
	e := row.Scan(&l.ID, &l.Code, &target, &l.Title, &cr, &ex, &pe, &la, &nx, &rev)
	if e != nil {
		return l, e
	}
	l.URL, e = s.decrypt(target)
	if e != nil {
		return l, fmt.Errorf("decrypt target: %w", e)
	}
	l.CreatedAt = time.Unix(0, cr).UTC()
	l.ExpiresAt = ptr(ex)
	l.PendingSince = ptr(pe)
	l.LastCheckedAt = ptr(la)
	l.NextCheckAt = ptr(nx)
	l.Revision = rev
	return l, nil
}
func (s *Store) Create(ctx context.Context, owner, id, code, url, title string, expiry *time.Time, idem string, bodyHash []byte) (Link, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Link{}, e
	}
	defer tx.Rollback()
	if idem != "" {
		var old []byte
		var lid string
		e = tx.QueryRowContext(ctx, "SELECT body_hash,link_id FROM idempotency WHERE owner=? AND key=?", owner, idem).Scan(&old, &lid)
		if e == nil {
			if string(old) != string(bodyHash) {
				return Link{}, ErrIdempotencyConflict
			}
			if e = tx.Rollback(); e != nil {
				return Link{}, e
			}
			return s.Get(ctx, owner, lid)
		}
		if e != sql.ErrNoRows {
			return Link{}, e
		}
	}
	target, e := s.encrypt(url)
	if e != nil {
		return Link{}, e
	}
	now := s.now().UTC()
	next := now.AddDate(0, 0, 7)
	_, e = tx.ExecContext(ctx, "INSERT INTO links(id,code_hash,code,owner,target,title,created_at,expires_at,next_check_at) VALUES(?,?,?,?,?,?,?,?,?)", id, codeHash(code), code, owner, target, title, now.UnixNano(), ns(expiry), next.UnixNano())
	if e != nil {
		return Link{}, e
	}
	if idem != "" {
		_, e = tx.ExecContext(ctx, "INSERT INTO idempotency(owner,key,body_hash,link_id) VALUES(?,?,?,?)", owner, idem, bodyHash, id)
		if e != nil {
			return Link{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return Link{}, e
	}
	return s.Get(ctx, owner, id)
}
func (s *Store) Get(ctx context.Context, owner, id string) (Link, error) {
	l, e := scan(s.db.QueryRowContext(ctx, "SELECT id,code,target,title,created_at,expires_at,pending_since,last_checked_at,next_check_at,revision FROM links WHERE owner=? AND id=? AND revoked_at IS NULL", owner, id), s)
	if e == sql.ErrNoRows {
		return l, ErrNotFound
	}
	return l, e
}
func (s *Store) List(ctx context.Context, owner string, limit int) ([]Link, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT id,code,target,title,created_at,expires_at,pending_since,last_checked_at,next_check_at,revision FROM links WHERE owner=? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT ?", owner, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, e := scan(rows, s)
		if e != nil {
			return nil, e
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
func (s *Store) Resolve(ctx context.Context, code string) (Link, error) {
	var l Link
	var target []byte
	var cr int64
	var ex sql.NullInt64
	e := s.db.QueryRowContext(ctx, "SELECT id,code,target,title,created_at,expires_at FROM links WHERE code_hash=? AND revoked_at IS NULL", codeHash(code)).Scan(&l.ID, &l.Code, &target, &l.Title, &cr, &ex)
	if e == sql.ErrNoRows {
		return l, ErrNotFound
	}
	if e != nil {
		return l, e
	}
	l.URL, e = s.decrypt(target)
	if e != nil {
		return l, e
	}
	l.CreatedAt = time.Unix(0, cr).UTC()
	l.ExpiresAt = ptr(ex)
	return l, nil
}
func (s *Store) Revoke(ctx context.Context, owner, id string) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var h []byte
	e = tx.QueryRowContext(ctx, "SELECT code_hash FROM links WHERE owner=? AND id=? AND revoked_at IS NULL", owner, id).Scan(&h)
	if e == sql.ErrNoRows {
		return ErrNotFound
	}
	if e != nil {
		return e
	}
	n := s.now().UTC().UnixNano()
	if _, e = tx.ExecContext(ctx, "UPDATE links SET revoked_at=?, target=X'',revision=revision+1 WHERE id=?", n, id); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO retired_codes(code_hash,retired_at) VALUES(?,?)", h, n); e != nil {
		return e
	}
	return tx.Commit()
}

// Due obtains leased candidates; callers must finish with Complete.
func (s *Store) Due(ctx context.Context, limit int, lease time.Duration) ([]Link, error) {
	now := s.now().UTC()
	rows, e := s.db.QueryContext(ctx, "SELECT id,code,target,title,created_at,expires_at,pending_since,last_checked_at,next_check_at,revision FROM links WHERE revoked_at IS NULL AND next_check_at<=? AND (lease_until IS NULL OR lease_until<?) LIMIT ?", now.UnixNano(), now.UnixNano(), limit)
	if e != nil {
		return nil, e
	}
	var candidates []Link
	for rows.Next() {
		l, err := scan(rows, s)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, l)
	}
	if e = rows.Err(); e != nil {
		_ = rows.Close()
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	var ret []Link
	for _, l := range candidates {
		r, err := s.db.ExecContext(ctx, "UPDATE links SET lease_until=?,revision=revision+1 WHERE id=? AND revision=? AND revoked_at IS NULL AND (lease_until IS NULL OR lease_until<?)", now.Add(lease).UnixNano(), l.ID, l.Revision, now.UnixNano())
		if err != nil {
			return nil, err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 1 {
			l.Revision++
			ret = append(ret, l)
		}
	}
	return ret, nil
}

func (s *Store) Complete(ctx context.Context, l Link, verdict string) error {
	now := s.now().UTC()
	next := now.AddDate(0, 0, 7)
	pending := l.PendingSince
	deleteIt := verdict == "missing" && pending != nil && now.Sub(*pending) >= 7*24*time.Hour
	if verdict == "missing" && pending == nil {
		pending = &now
	}
	if verdict == "healthy" {
		pending = nil
	}
	if deleteIt {
		return s.RevokeSystem(ctx, l.ID, l.Revision)
	}
	_, e := s.db.ExecContext(ctx, "UPDATE links SET pending_since=?,last_checked_at=?,next_check_at=?,lease_until=NULL,revision=revision+1 WHERE id=? AND revision=? AND revoked_at IS NULL", ns(pending), now.UnixNano(), next.UnixNano(), l.ID, l.Revision)
	return e
}
func (s *Store) RevokeSystem(ctx context.Context, id string, rev int64) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var h []byte
	e = tx.QueryRowContext(ctx, "SELECT code_hash FROM links WHERE id=? AND revision=? AND revoked_at IS NULL", id, rev).Scan(&h)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	n := s.now().UTC().UnixNano()
	_, e = tx.ExecContext(ctx, "UPDATE links SET revoked_at=?,target=X'',lease_until=NULL WHERE id=? AND revision=?", n, id, rev)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO retired_codes(code_hash,retired_at) VALUES(?,?)", h, n)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func BodyHash(v []byte) []byte  { h := sha256.Sum256(v); return h[:] }
func EncodeKey(v []byte) string { return base64.RawStdEncoding.EncodeToString(v) }
