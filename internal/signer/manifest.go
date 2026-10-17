package signer

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
)

type activationManifest struct {
	KeyID        string   `json:"key_id"`
	Epoch        uint64   `json:"epoch"`
	PublicKey    string   `json:"public_key_uncompressed"`
	ReadyParties []string `json:"ready_parties"`
}

// ActivationManifestSHA256 returns the canonical manifest hash expected by
// every signer. Party order is normalized before encoding.
func ActivationManifestSHA256(keyID string, epoch uint64, publicKey string, readyParties []string) ([32]byte, error) {
	if keyID == "" || epoch == 0 || publicKey == "" || len(readyParties) < 2 || len(readyParties) > 3 {
		return [32]byte{}, errors.New("incomplete activation manifest")
	}
	parties := append([]string(nil), readyParties...)
	sort.Strings(parties)
	for i, id := range parties {
		if id == "" || (i > 0 && id == parties[i-1]) {
			return [32]byte{}, errors.New("activation manifest parties must be nonempty and unique")
		}
	}
	encoded, err := json.Marshal(activationManifest{KeyID: keyID, Epoch: epoch, PublicKey: publicKey, ReadyParties: parties})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
