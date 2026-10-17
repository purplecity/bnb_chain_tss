// Package sharestore provides an authenticated encryption envelope for a
// complete BNB tss-lib LocalPartySaveData value. Key wrapping and durable
// storage are intentionally provided by the caller.
package sharestore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

const SchemaVersion = 1

var ErrIdentityMismatch = errors.New("share envelope identity mismatch")

type Identity struct {
	KeyID  string `json:"key_id"`
	Epoch  uint64 `json:"epoch"`
	Party  string `json:"party_id"`
	Schema uint32 `json:"schema_version"`
}

type Envelope struct {
	Identity   Identity `json:"identity"`
	Nonce      []byte   `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
}

func (i Identity) validate() error {
	if i.KeyID == "" || i.Party == "" || i.Epoch == 0 || i.Schema != SchemaVersion {
		return fmt.Errorf("invalid share identity or unsupported schema")
	}
	return nil
}

func (e Envelope) Validate() error {
	if err := e.Identity.validate(); err != nil {
		return err
	}
	if len(e.Nonce) != 12 || len(e.Ciphertext) < 16 {
		return errors.New("malformed share envelope")
	}
	return nil
}

// Encrypt serializes and encrypts all of saveData. The caller must supply a
// fresh random 32-byte data key and wrap it independently for online and
// recovery use before persisting the envelope.
func Encrypt(saveData keygen.LocalPartySaveData, identity Identity, dataKey []byte) (Envelope, error) {
	if err := identity.validate(); err != nil {
		return Envelope{}, err
	}
	if len(dataKey) != 32 {
		return Envelope{}, errors.New("data key must be 32 bytes")
	}
	plaintext, err := json.Marshal(saveData)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal share data: %w", err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	return Envelope{
		Identity:   identity,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, associatedData(identity)),
	}, nil
}

// Decrypt checks the expected identity before authenticating and decoding the
// complete share object. Identity fields are also bound as AEAD associated data.
func Decrypt(envelope Envelope, expected Identity, dataKey []byte) (keygen.LocalPartySaveData, error) {
	if err := envelope.Validate(); err != nil {
		return keygen.LocalPartySaveData{}, err
	}
	if err := expected.validate(); err != nil {
		return keygen.LocalPartySaveData{}, err
	}
	if envelope.Identity != expected {
		return keygen.LocalPartySaveData{}, ErrIdentityMismatch
	}
	if len(dataKey) != 32 {
		return keygen.LocalPartySaveData{}, errors.New("data key must be 32 bytes")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return keygen.LocalPartySaveData{}, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keygen.LocalPartySaveData{}, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData(envelope.Identity))
	if err != nil {
		return keygen.LocalPartySaveData{}, fmt.Errorf("authenticate share envelope: %w", err)
	}
	var saveData keygen.LocalPartySaveData
	if err := json.Unmarshal(plaintext, &saveData); err != nil {
		return keygen.LocalPartySaveData{}, fmt.Errorf("unmarshal share data: %w", err)
	}
	return saveData, nil
}

func associatedData(i Identity) []byte {
	data, _ := json.Marshal(i) // Identity contains only deterministic scalar/string fields.
	return data
}
