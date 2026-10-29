package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secret(t *testing.T, name, value string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if e := os.WriteFile(p, []byte(value), mode); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestReadPrivateRejectsEmptyAndInsecureFiles(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		mode        os.FileMode
	}{{"empty", " \n", 0600}, {"world", "x", 0644}, {"large", strings.Repeat("x", 4097), 0600}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := ReadPrivate(secret(t, "key", tc.value, tc.mode)); e == nil {
				t.Fatal("expected error")
			}
		})
	}
}
func TestReadPrivateRejectsSymlink(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if e := os.WriteFile(target, []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(d, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPrivate(link); e == nil {
		t.Fatal("expected symlink rejection")
	}
}
func TestEnsurePrivateDBDirDoesNotRepairInsecureExisting(t *testing.T) {
	d := t.TempDir()
	if e := os.Chmod(d, 0755); e != nil {
		t.Fatal(e)
	}
	if e := EnsurePrivateDBDir(filepath.Join(d, "x.db")); e == nil {
		t.Fatal("expected insecure directory rejection")
	}
}
