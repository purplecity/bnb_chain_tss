// Package policy validates a transaction request before chain-specific code
// decodes it and derives the digest sent to the TSS protocol.
package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

type Intent struct {
	RequestID     string    `json:"request_id"`
	KeyID         string    `json:"key_id"`
	Epoch         uint64    `json:"epoch"`
	Chain         string    `json:"chain"`
	Network       string    `json:"network"`
	To            string    `json:"to"`
	Value         *big.Int  `json:"value"`
	ExpiresAt     time.Time `json:"expires_at"`
	ApprovalProof []byte    `json:"approval_proof"`
	UnsignedTx    []byte    `json:"unsigned_tx"`
}

type Rules struct {
	KeyID               string
	Epoch               uint64
	Chain               string
	Network             string
	AllowedDestinations map[string]struct{} // lowercase, normalized form
	MaxValue            *big.Int
	MaxLifetime         time.Duration
}

type ApprovalVerifier interface{ Verify(intent Intent) error }
type ApprovalVerifierFunc func(Intent) error

func (f ApprovalVerifierFunc) Verify(i Intent) error { return f(i) }

func Validate(intent Intent, rules Rules, now time.Time, approvals ApprovalVerifier) error {
	if strings.TrimSpace(intent.RequestID) == "" || intent.KeyID == "" || intent.Epoch == 0 || intent.Value == nil || intent.Value.Sign() < 0 || len(intent.UnsignedTx) == 0 {
		return errors.New("incomplete or invalid signing intent")
	}
	if intent.KeyID != rules.KeyID || intent.Epoch != rules.Epoch {
		return errors.New("key or epoch does not match active policy")
	}
	if intent.Chain != rules.Chain || intent.Network != rules.Network {
		return errors.New("chain or network is not allowed")
	}
	if rules.MaxValue == nil || rules.MaxValue.Sign() < 0 || intent.Value.Cmp(rules.MaxValue) > 0 {
		return errors.New("transaction value exceeds policy")
	}
	if intent.To == "" || len(rules.AllowedDestinations) == 0 {
		return errors.New("destination is not allowed")
	}
	if _, ok := rules.AllowedDestinations[strings.ToLower(intent.To)]; !ok {
		return errors.New("destination is not allowed")
	}
	if rules.MaxLifetime <= 0 || !intent.ExpiresAt.After(now) || intent.ExpiresAt.After(now.Add(rules.MaxLifetime)) {
		return errors.New("signing intent is expired or exceeds maximum lifetime")
	}
	if approvals == nil || len(intent.ApprovalProof) == 0 {
		return errors.New("approval proof is required")
	}
	return approvals.Verify(intent)
}

type ApprovalClaims struct {
	RequestID          string `json:"request_id"`
	KeyID              string `json:"key_id"`
	Epoch              uint64 `json:"epoch"`
	Chain              string `json:"chain"`
	Network            string `json:"network"`
	UnsignedTxSHA256   string `json:"unsigned_tx_sha256"`
	ExpiresAtUnixMilli int64  `json:"expires_at_unix_milli"`
}

type ApprovalSignature struct {
	ApproverID string `json:"approver_id"`
	Signature  []byte `json:"signature"`
}
type ApprovalProof struct {
	Claims     ApprovalClaims      `json:"claims"`
	Signatures []ApprovalSignature `json:"signatures"`
}

type Ed25519Quorum struct {
	PublicKeys map[string]ed25519.PublicKey
	Threshold  int
}

func ClaimsForIntent(intent Intent) ApprovalClaims {
	txHash := sha256.Sum256(intent.UnsignedTx)
	return ApprovalClaims{RequestID: intent.RequestID, KeyID: intent.KeyID, Epoch: intent.Epoch, Chain: intent.Chain, Network: intent.Network, UnsignedTxSHA256: hex.EncodeToString(txHash[:]), ExpiresAtUnixMilli: intent.ExpiresAt.UnixMilli()}
}

func ApprovalSigningBytes(claims ApprovalClaims) ([]byte, error) { return json.Marshal(claims) }

func (v Ed25519Quorum) Verify(intent Intent) error {
	if v.Threshold < 1 || v.Threshold > len(v.PublicKeys) {
		return errors.New("invalid approver threshold")
	}
	decoder := json.NewDecoder(bytes.NewReader(intent.ApprovalProof))
	decoder.DisallowUnknownFields()
	var proof ApprovalProof
	if err := decoder.Decode(&proof); err != nil {
		return fmt.Errorf("decode approval proof: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("approval proof contains trailing data")
	}
	expected := ClaimsForIntent(intent)
	expectedBytes, _ := ApprovalSigningBytes(expected)
	actualBytes, _ := ApprovalSigningBytes(proof.Claims)
	if !bytes.Equal(expectedBytes, actualBytes) {
		return errors.New("approval proof does not bind the exact signing intent")
	}
	seen := map[string]struct{}{}
	valid := 0
	for _, signature := range proof.Signatures {
		key, ok := v.PublicKeys[signature.ApproverID]
		if !ok {
			return fmt.Errorf("unknown approver %q", signature.ApproverID)
		}
		if _, ok := seen[signature.ApproverID]; ok {
			return errors.New("duplicate approver signature")
		}
		seen[signature.ApproverID] = struct{}{}
		payload, _ := ApprovalSigningBytes(proof.Claims)
		if !ed25519.Verify(key, payload, signature.Signature) {
			return fmt.Errorf("invalid approval signature from %q", signature.ApproverID)
		}
		valid++
	}
	if valid < v.Threshold {
		return errors.New("approval signature quorum not met")
	}
	return nil
}
