package sharestore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type fakeKMS struct {
	keyID string
	key   []byte
}

func (f fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if aws.ToString(in.KeyId) != f.keyID {
		return nil, errors.New("wrong KMS key")
	}
	aead := mustAEAD(f.key)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nonce, nonce, in.Plaintext, encodeContext(in.EncryptionContext))
	return &kms.EncryptOutput{CiphertextBlob: ct, KeyId: aws.String(f.keyID)}, nil
}
func (f fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if aws.ToString(in.KeyId) != f.keyID {
		return nil, errors.New("wrong KMS key")
	}
	aead := mustAEAD(f.key)
	if len(in.CiphertextBlob) < aead.NonceSize() {
		return nil, errors.New("short ciphertext")
	}
	nonce := in.CiphertextBlob[:aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, in.CiphertextBlob[aead.NonceSize():], encodeContext(in.EncryptionContext))
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{Plaintext: plain, KeyId: aws.String(f.keyID)}, nil
}
func mustAEAD(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}
func encodeContext(context map[string]string) []byte {
	out := []byte{}
	for _, key := range []string{"service", "key_id", "epoch", "party_id", "schema_version"} {
		out = append(out, []byte(context[key])...)
		out = append(out, 0)
	}
	return out
}

func TestAWSKMSWrapperBindsIdentityInContext(t *testing.T) {
	client := fakeKMS{keyID: "arn:aws:kms:region:account:key/online", key: make([]byte, 32)}
	wrapper := AWSKMSWrapper{Client: client, KeyID: client.keyID}
	identity := Identity{KeyID: "wallet-1", Epoch: 7, Party: "signer-b", Schema: SchemaVersion}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapper.Wrap(context.Background(), identity, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := wrapper.Unwrap(context.Background(), identity, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, dataKey) {
		t.Fatal("KMS wrapper changed data key")
	}
	wrong := identity
	wrong.Epoch++
	if _, err := wrapper.Unwrap(context.Background(), wrong, wrapped); err == nil {
		t.Fatal("wrong identity restored KMS wrapped data key")
	}
}
