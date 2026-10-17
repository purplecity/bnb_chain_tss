package sharestore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

func TestEnvelopeAuthenticationAndIdentityBinding(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	identity := Identity{KeyID: "wallet-key-1", Epoch: 1, Party: "signer-a", Schema: SchemaVersion}
	save := keygen.NewLocalPartySaveData(3)
	save.LocalSecrets.Xi = byteInt(12345)
	save.LocalSecrets.ShareID = byteInt(7)
	envelope, err := Encrypt(save, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decrypt(envelope, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Xi.Cmp(save.Xi) != 0 || decoded.ShareID.Cmp(save.ShareID) != 0 || len(decoded.Ks) != 3 {
		t.Fatal("complete share data did not survive round trip")
	}

	wrongIdentity := identity
	wrongIdentity.Party = "signer-b"
	if _, err := Decrypt(envelope, wrongIdentity, key); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
	wrongKey := bytes.Repeat([]byte{0x99}, 32)
	if _, err := Decrypt(envelope, identity, wrongKey); err == nil {
		t.Fatal("expected wrong key to fail authentication")
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if _, err := Decrypt(tampered, identity, key); err == nil {
		t.Fatal("expected tampered ciphertext to fail authentication")
	}
}

func TestEnvelopeRejectsInvalidInputs(t *testing.T) {
	identity := Identity{KeyID: "key", Epoch: 1, Party: "p0", Schema: SchemaVersion}
	if _, err := Encrypt(keygen.LocalPartySaveData{}, identity, []byte("short")); err == nil {
		t.Fatal("expected invalid key length to fail")
	}
	if _, err := Encrypt(keygen.LocalPartySaveData{}, Identity{}, make([]byte, 32)); err == nil {
		t.Fatal("expected invalid identity to fail")
	}
	if err := (Envelope{Identity: identity}).Validate(); err == nil {
		t.Fatal("expected malformed envelope to fail")
	}
}

func byteInt(v int64) *big.Int { return big.NewInt(v) }
