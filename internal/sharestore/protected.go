package sharestore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

type WrappedKey struct {
	KeyReference string `json:"key_reference"`
	Ciphertext   []byte `json:"ciphertext"`
}

type Record struct {
	Identity    Identity   `json:"identity"`
	Envelope    Envelope   `json:"envelope"`
	OnlineKey   WrappedKey `json:"online_key"`
	RecoveryKey WrappedKey `json:"recovery_key"`
}

// KeyWrapper wraps a random data-encryption key under one independent KMS or
// recovery key. Implementations must bind the supplied identity as encryption
// context and must not log plaintextKey.
type KeyWrapper interface {
	Wrap(ctx context.Context, identity Identity, plaintextKey []byte) (WrappedKey, error)
	Unwrap(ctx context.Context, identity Identity, wrapped WrappedKey) ([]byte, error)
}

func Protect(ctx context.Context, saveData keygen.LocalPartySaveData, identity Identity, online, recovery KeyWrapper) (Record, error) {
	if online == nil || recovery == nil {
		return Record{}, errors.New("independent online and recovery key wrappers are required")
	}
	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Record{}, fmt.Errorf("generate share data key: %w", err)
	}
	defer wipe(dataKey)
	envelope, err := Encrypt(saveData, identity, dataKey)
	if err != nil {
		return Record{}, err
	}
	onlineKey, err := online.Wrap(ctx, identity, dataKey)
	if err != nil {
		return Record{}, fmt.Errorf("wrap online data key: %w", err)
	}
	recoveryKey, err := recovery.Wrap(ctx, identity, dataKey)
	if err != nil {
		return Record{}, fmt.Errorf("wrap recovery data key: %w", err)
	}
	if onlineKey.KeyReference == recoveryKey.KeyReference {
		return Record{}, errors.New("online and recovery wraps must use different key references")
	}
	return Record{Identity: identity, Envelope: envelope, OnlineKey: onlineKey, RecoveryKey: recoveryKey}, nil
}

func (r Record) Validate() error {
	if err := r.Identity.validate(); err != nil {
		return err
	}
	if r.Envelope.Identity != r.Identity {
		return ErrIdentityMismatch
	}
	if err := r.Envelope.Validate(); err != nil {
		return err
	}
	if r.OnlineKey.KeyReference == "" || len(r.OnlineKey.Ciphertext) == 0 || r.RecoveryKey.KeyReference == "" || len(r.RecoveryKey.Ciphertext) == 0 {
		return errors.New("record must have both online and recovery key wraps")
	}
	if r.OnlineKey.KeyReference == r.RecoveryKey.KeyReference {
		return errors.New("online and recovery wraps must use different key references")
	}
	return nil
}

func RestoreOnline(ctx context.Context, r Record, wrapper KeyWrapper) (keygen.LocalPartySaveData, error) {
	return restore(ctx, r, wrapper, r.OnlineKey)
}

func RestoreRecovery(ctx context.Context, r Record, wrapper KeyWrapper) (keygen.LocalPartySaveData, error) {
	return restore(ctx, r, wrapper, r.RecoveryKey)
}

func restore(ctx context.Context, r Record, wrapper KeyWrapper, wrapped WrappedKey) (keygen.LocalPartySaveData, error) {
	if err := r.Validate(); err != nil {
		return keygen.LocalPartySaveData{}, err
	}
	if wrapper == nil {
		return keygen.LocalPartySaveData{}, errors.New("key wrapper is required")
	}
	dataKey, err := wrapper.Unwrap(ctx, r.Identity, wrapped)
	if err != nil {
		return keygen.LocalPartySaveData{}, fmt.Errorf("unwrap share data key: %w", err)
	}
	defer wipe(dataKey)
	return Decrypt(r.Envelope, r.Identity, dataKey)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
