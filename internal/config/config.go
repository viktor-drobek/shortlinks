package config

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSecretFileBytes = 4096

type Config struct{ DBPath, KeyFile, ProxyKeyFile, BaseURL string }

func ReadKey(path string) ([]byte, error) {
	b, err := readPrivateRegular(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("key file must contain exactly 32 bytes of hexadecimal")
	}
	return key, nil
}

func ReadPrivate(path string) ([]byte, error) {
	b, err := readPrivateRegular(path)
	if err != nil {
		return nil, err
	}
	key := []byte(strings.TrimSpace(string(b)))
	if len(key) == 0 {
		return nil, errors.New("private key file is empty")
	}
	return key, nil
}

func readPrivateRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("secret file must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file %q must not be accessible by group or other users", path)
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied secret path, checked with Lstat and SameFile/fstat.
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || !os.SameFile(info, opened) {
		return nil, errors.New("secret file changed during open")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretFileBytes {
		return nil, errors.New("secret file is too large")
	}
	return b, nil
}

// EnsurePrivateDBDir creates the DB directory when absent. Existing directories
// are only validated; their permissions are never changed by this process.
func EnsurePrivateDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("database directory must be a directory, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("database directory %q must not be accessible by group or other users", dir)
	}
	return nil
}
func Equal(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }
