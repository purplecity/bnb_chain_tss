package sharestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var ErrRecordExists = errors.New("immutable share record already exists")

// FileStore is a local encrypted-record store for development and recovery
// drills. Production should implement the same immutable contract with S3
// versioning/Object Lock and a separately controlled recovery account.
type FileStore struct{ Root string }

func (s FileStore) Put(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Root == "" {
		return errors.New("share store root is required")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	path := s.path(record.Identity)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create share store directory: %w", err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode share record: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".share-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Equal(existing, encoded) {
				return nil
			}
			return ErrRecordExists
		}
		return fmt.Errorf("write immutable share record: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	if err != nil {
		return fmt.Errorf("sync share store directory: %w", err)
	}
	return nil
}

func (s FileStore) Get(ctx context.Context, identity Identity) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := identity.validate(); err != nil {
		return Record{}, err
	}
	encoded, err := os.Open(s.path(identity))
	if err != nil {
		return Record{}, err
	}
	defer encoded.Close()
	data, err := io.ReadAll(io.LimitReader(encoded, 64<<20))
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("decode share record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if record.Identity != identity {
		return Record{}, ErrIdentityMismatch
	}
	return record, nil
}

func (s FileStore) path(identity Identity) string {
	encoded, _ := json.Marshal(identity)
	id := sha256.Sum256(encoded)
	return filepath.Join(s.Root, hex.EncodeToString(id[:])+".json")
}
