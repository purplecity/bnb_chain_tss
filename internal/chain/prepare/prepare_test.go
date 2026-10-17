package prepare

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/internal/chain/evm"
	"github.com/purplecity/bnb_chain_tss/internal/policy"
)

func TestEVMPreparationRequiresExactApprovedTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(1)
	destination := common.HexToAddress("0xabc0000000000000000000000000000000000001")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 9, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(5), Gas: 21000, To: &destination, Value: big.NewInt(12)})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	intent := policy.Intent{RequestID: "r-100", KeyID: "key-1", Epoch: 2, Chain: "evm", Network: "mainnet", To: destination.Hex(), Value: big.NewInt(12), ExpiresAt: now.Add(time.Minute), UnsignedTx: raw}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := policy.ApprovalSigningBytes(policy.ClaimsForIntent(intent))
	if err != nil {
		t.Fatal(err)
	}
	intent.ApprovalProof, _ = json.Marshal(policy.ApprovalProof{Claims: policy.ClaimsForIntent(intent), Signatures: []policy.ApprovalSignature{{ApproverID: "alice", Signature: ed25519.Sign(priv, payload)}}})
	policyRules := policy.Rules{KeyID: "key-1", Epoch: 2, Chain: "evm", Network: "mainnet", AllowedDestinations: map[string]struct{}{strings.ToLower(destination.Hex()): {}}, MaxValue: big.NewInt(20), MaxLifetime: 5 * time.Minute}
	nonce := uint64(9)
	chainRules := evm.Rules{ChainID: chainID, ExpectedSender: crypto.PubkeyToAddress(key.PublicKey), AllowedDestinations: map[common.Address]struct{}{destination: {}}, MaxValue: big.NewInt(20), MaxGas: 30000, MaxGasPrice: big.NewInt(10), MaxTotalCost: big.NewInt(500000), ExpectedNonce: &nonce}
	verifier := policy.Ed25519Quorum{PublicKeys: map[string]ed25519.PublicKey{"alice": pub}, Threshold: 1}
	prepared, err := EVM(intent, policyRules, chainRules, now, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Transaction.Nonce() != nonce || prepared.Digest == ([32]byte{}) {
		t.Fatal("preparation returned wrong tx or digest")
	}
	changed := intent
	changed.UnsignedTx = append([]byte(nil), intent.UnsignedTx...)
	changed.UnsignedTx[len(changed.UnsignedTx)-1] ^= 1
	if _, err := EVM(changed, policyRules, chainRules, now, verifier); err == nil {
		t.Fatal("modified transaction was approved")
	}
	changed = intent
	changed.To = "0xabc0000000000000000000000000000000000002"
	if _, err := EVM(changed, policyRules, chainRules, now, verifier); err == nil {
		t.Fatal("intent destination mismatch was approved")
	}
}
