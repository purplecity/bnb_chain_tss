package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestValidateIntent(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	intent := Intent{RequestID: "request-1", KeyID: "key-1", Epoch: 2, Chain: "evm", Network: "sepolia", To: "0xabc", Value: big.NewInt(9), ExpiresAt: now.Add(time.Minute), ApprovalProof: []byte("signed-approval"), UnsignedTx: []byte("canonical-tx")}
	rules := Rules{KeyID: "key-1", Epoch: 2, Chain: "evm", Network: "sepolia", AllowedDestinations: map[string]struct{}{"0xabc": {}}, MaxValue: big.NewInt(10), MaxLifetime: 5 * time.Minute}
	accept := ApprovalVerifierFunc(func(got Intent) error {
		if got.RequestID != intent.RequestID {
			return errors.New("wrong request")
		}
		return nil
	})
	if err := Validate(intent, rules, now, accept); err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}

	cases := map[string]func(*Intent, *Rules){
		"wrong key":           func(i *Intent, _ *Rules) { i.KeyID = "other" },
		"wrong epoch":         func(i *Intent, _ *Rules) { i.Epoch++ },
		"wrong network":       func(i *Intent, _ *Rules) { i.Network = "mainnet" },
		"unknown destination": func(i *Intent, _ *Rules) { i.To = "0xdef" },
		"over value limit":    func(i *Intent, _ *Rules) { i.Value = big.NewInt(11) },
		"negative value":      func(i *Intent, _ *Rules) { i.Value = big.NewInt(-1) },
		"expired":             func(i *Intent, _ *Rules) { i.ExpiresAt = now },
		"too long":            func(i *Intent, _ *Rules) { i.ExpiresAt = now.Add(6 * time.Minute) },
		"missing approval":    func(i *Intent, _ *Rules) { i.ApprovalProof = nil },
		"missing request":     func(i *Intent, _ *Rules) { i.RequestID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i, r := intent, rules
			mutate(&i, &r)
			if err := Validate(i, r, now, accept); err == nil {
				t.Fatal("expected policy rejection")
			}
		})
	}
	if err := Validate(intent, rules, now, nil); err == nil {
		t.Fatal("expected missing verifier rejection")
	}
	if err := Validate(intent, rules, now, ApprovalVerifierFunc(func(Intent) error { return errors.New("approval rejected") })); err == nil {
		t.Fatal("expected verifier rejection")
	}
}

func TestEd25519ApprovalQuorumBindsExactIntent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	intent := Intent{RequestID: "req-ed25519", KeyID: "key", Epoch: 4, Chain: "evm", Network: "mainnet", To: "0x1234", Value: big.NewInt(5), ExpiresAt: now.Add(time.Minute), UnsignedTx: []byte{1, 2, 3}}
	keys := map[string]ed25519.PublicKey{}
	signatures := make([]ApprovalSignature, 0, 2)
	for _, id := range []string{"approver-a", "approver-b"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = pub
		payload, err := ApprovalSigningBytes(ClaimsForIntent(intent))
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, ApprovalSignature{ApproverID: id, Signature: ed25519.Sign(priv, payload)})
	}
	proof, err := json.Marshal(ApprovalProof{Claims: ClaimsForIntent(intent), Signatures: signatures})
	if err != nil {
		t.Fatal(err)
	}
	intent.ApprovalProof = proof
	verifier := Ed25519Quorum{PublicKeys: keys, Threshold: 2}
	if err := verifier.Verify(intent); err != nil {
		t.Fatalf("valid approver quorum rejected: %v", err)
	}
	mutated := intent
	mutated.UnsignedTx = []byte{1, 2, 4}
	if err := verifier.Verify(mutated); err == nil {
		t.Fatal("proof accepted a changed raw transaction")
	}
	mutated = intent
	mutated.Epoch++
	if err := verifier.Verify(mutated); err == nil {
		t.Fatal("proof accepted a changed epoch")
	}
	insufficient, _ := json.Marshal(ApprovalProof{Claims: ClaimsForIntent(intent), Signatures: signatures[:1]})
	mutated = intent
	mutated.ApprovalProof = insufficient
	if err := verifier.Verify(mutated); err == nil {
		t.Fatal("proof below quorum accepted")
	}
	duplicate, _ := json.Marshal(ApprovalProof{Claims: ClaimsForIntent(intent), Signatures: []ApprovalSignature{signatures[0], signatures[0]}})
	mutated = intent
	mutated.ApprovalProof = duplicate
	if err := verifier.Verify(mutated); err == nil {
		t.Fatal("duplicate approver counted twice")
	}
	badSignature := append([]ApprovalSignature(nil), signatures...)
	badSignature[0].Signature = append([]byte(nil), badSignature[0].Signature...)
	badSignature[0].Signature[0] ^= 1
	badProof, _ := json.Marshal(ApprovalProof{Claims: ClaimsForIntent(intent), Signatures: badSignature})
	mutated = intent
	mutated.ApprovalProof = badProof
	if err := verifier.Verify(mutated); err == nil {
		t.Fatal("invalid approver signature accepted")
	}
}
