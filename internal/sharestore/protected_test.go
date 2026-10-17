package sharestore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

type testWrapper struct {
	id  string
	key []byte
}

func (w testWrapper) Wrap(_ context.Context, identity Identity, plaintext []byte) (WrappedKey, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return WrappedKey{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{KeyReference: w.id, Ciphertext: aead.Seal(nonce, nonce, plaintext, associatedData(identity))}, nil
}
func (w testWrapper) Unwrap(_ context.Context, identity Identity, wrapped WrappedKey) ([]byte, error) {
	if wrapped.KeyReference != w.id {
		return nil, errors.New("wrong test wrapping key")
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped.Ciphertext) < aead.NonceSize() {
		return nil, errors.New("short wrapped value")
	}
	nonce := wrapped.Ciphertext[:aead.NonceSize()]
	return aead.Open(nil, nonce, wrapped.Ciphertext[aead.NonceSize():], associatedData(identity))
}

func TestProtectRestoreAndImmutableFileStore(t *testing.T) {
	ctx := context.Background()
	online := testWrapper{id: "online-kms", key: bytes.Repeat([]byte("o"), 32)}
	recovery := testWrapper{id: "recovery-kms", key: bytes.Repeat([]byte("r"), 32)}
	identity := Identity{KeyID: "key-42", Epoch: 3, Party: "party-a", Schema: SchemaVersion}
	save := keygen.NewLocalPartySaveData(3)
	save.Xi = bigInt(123)
	save.ShareID = bigInt(1)
	record, err := Protect(ctx, save, identity, online, recovery)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreOnline(ctx, record, online)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Xi.Cmp(save.Xi) != 0 || restored.ShareID.Cmp(save.ShareID) != 0 {
		t.Fatal("online restore changed share")
	}
	restored, err = RestoreRecovery(ctx, record, recovery)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Xi.Cmp(save.Xi) != 0 {
		t.Fatal("recovery restore changed share")
	}
	if _, err := RestoreRecovery(ctx, record, online); err == nil {
		t.Fatal("online key unexpectedly restored recovery-wrapped data")
	}

	store := FileStore{Root: filepath.Join(t.TempDir(), "shares")}
	if err := store.Put(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, record); err != nil {
		t.Fatalf("same immutable record should be idempotent: %v", err)
	}
	loaded, err := store.Get(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity != identity || loaded.OnlineKey.KeyReference != online.id {
		t.Fatal("stored record metadata changed")
	}
	path := store.path(identity)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("share file mode = %o, want 600", info.Mode().Perm())
	}
	changed := record
	changed.Envelope.Ciphertext = append([]byte(nil), record.Envelope.Ciphertext...)
	changed.Envelope.Ciphertext[0] ^= 1
	if err := store.Put(ctx, changed); !errors.Is(err, ErrRecordExists) {
		t.Fatalf("expected immutable collision, got %v", err)
	}
	if _, err := store.Get(ctx, Identity{KeyID: identity.KeyID, Epoch: identity.Epoch, Party: "party-b", Schema: SchemaVersion}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong identity lookup error = %v", err)
	}
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }
