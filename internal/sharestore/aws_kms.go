package sharestore

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type KMSAPI interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type AWSKMSWrapper struct {
	Client KMSAPI
	KeyID  string
}

func (w AWSKMSWrapper) Wrap(ctx context.Context, identity Identity, plaintextKey []byte) (WrappedKey, error) {
	if w.Client == nil || w.KeyID == "" || len(plaintextKey) != 32 {
		return WrappedKey{}, errors.New("KMS client, key ID and 32-byte data key are required")
	}
	out, err := w.Client.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(w.KeyID), Plaintext: plaintextKey, EncryptionContext: contextFor(identity)})
	if err != nil {
		return WrappedKey{}, err
	}
	if len(out.CiphertextBlob) == 0 || out.KeyId == nil {
		return WrappedKey{}, errors.New("KMS returned an incomplete wrapped key")
	}
	return WrappedKey{KeyReference: aws.ToString(out.KeyId), Ciphertext: append([]byte(nil), out.CiphertextBlob...)}, nil
}

func (w AWSKMSWrapper) Unwrap(ctx context.Context, identity Identity, wrapped WrappedKey) ([]byte, error) {
	if w.Client == nil || wrapped.KeyReference == "" || len(wrapped.Ciphertext) == 0 {
		return nil, errors.New("KMS client and wrapped key are required")
	}
	out, err := w.Client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(wrapped.KeyReference), CiphertextBlob: wrapped.Ciphertext, EncryptionContext: contextFor(identity)})
	if err != nil {
		return nil, err
	}
	if len(out.Plaintext) != 32 {
		return nil, errors.New("KMS returned an invalid data key")
	}
	return append([]byte(nil), out.Plaintext...), nil
}

func contextFor(i Identity) map[string]string {
	return map[string]string{"service": "bnb-mpc-wallet", "key_id": i.KeyID, "epoch": fmt.Sprintf("%d", i.Epoch), "party_id": i.Party, "schema_version": fmt.Sprintf("%d", i.Schema)}
}
