package evm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
)

type allowCall struct{}

func (allowCall) ValidateCall(common.Address, *big.Int, []byte) error { return nil }

type denyCall struct{}

func (denyCall) ValidateCall(common.Address, *big.Int, []byte) error {
	return errors.New("selector not allowed")
}

func TestEIP1559ValidateSignEncodeAndRecover(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(11155111)
	to := common.HexToAddress("0x1234567890123456789012345678901234567890")
	unsigned := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 7, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(20), Gas: 21000, To: &to, Value: big.NewInt(100)})
	raw, err := unsigned.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(7)
	rules := Rules{ChainID: chainID, ExpectedSender: crypto.PubkeyToAddress(key.PublicKey), AllowedDestinations: map[common.Address]struct{}{to: {}}, MaxValue: big.NewInt(1000), MaxGas: 50000, MaxGasPrice: big.NewInt(30), MaxTotalCost: big.NewInt(2_000_000), ExpectedNonce: &nonce}
	validated, err := ValidateUnsigned(raw, rules)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := crypto.Sign(validated.Digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	sig := tssadapter.Signature{R: new(big.Int).SetBytes(compact[:32]), S: new(big.Int).SetBytes(compact[32:64]), RecoveryID: compact[64]}
	signedRaw, err := AttachSignature(validated, sig, rules.ExpectedSender)
	if err != nil {
		t.Fatal(err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(signedRaw); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(validated.Signer, signed)
	if err != nil || from != rules.ExpectedSender {
		t.Fatalf("signed transaction recovered wrong sender: %s, %v", from, err)
	}
	if _, err := ValidateUnsigned(signedRaw, rules); err == nil {
		t.Fatal("already signed transaction must be rejected")
	}
}

func TestLegacyTxUsesConfiguredEIP155ChainID(t *testing.T) {
	key, _ := crypto.GenerateKey()
	to := common.HexToAddress("0x2000000000000000000000000000000000000001")
	tx := types.NewTx(&types.LegacyTx{Nonce: 3, GasPrice: big.NewInt(1), Gas: 21000, To: &to, Value: big.NewInt(1)})
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	nonce := uint64(3)
	rules := Rules{ChainID: big.NewInt(1), ExpectedSender: crypto.PubkeyToAddress(key.PublicKey), AllowedDestinations: map[common.Address]struct{}{to: {}}, MaxValue: big.NewInt(10), MaxGas: 30000, MaxGasPrice: big.NewInt(2), MaxTotalCost: big.NewInt(100000), ExpectedNonce: &nonce}
	validated, err := ValidateUnsigned(raw, rules)
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := crypto.Sign(validated.Digest[:], key)
	signedRaw, err := AttachSignature(validated, tssadapter.Signature{R: new(big.Int).SetBytes(compact[:32]), S: new(big.Int).SetBytes(compact[32:64]), RecoveryID: compact[64]}, rules.ExpectedSender)
	if err != nil {
		t.Fatal(err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(signedRaw); err != nil {
		t.Fatal(err)
	}
	if signed.ChainId().Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("legacy tx was not replay-protected: chain ID %s", signed.ChainId())
	}
}

func TestEVMPolicyRejectsUnsafeCases(t *testing.T) {
	key, _ := crypto.GenerateKey()
	to := common.HexToAddress("0x3000000000000000000000000000000000000001")
	base := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 4, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(4), Gas: 21000, To: &to, Value: big.NewInt(1)})
	marshal := func(tx *types.Transaction) []byte {
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	nonce := uint64(4)
	rules := Rules{ChainID: big.NewInt(1), ExpectedSender: crypto.PubkeyToAddress(key.PublicKey), AllowedDestinations: map[common.Address]struct{}{to: {}}, MaxValue: big.NewInt(10), MaxGas: 30000, MaxGasPrice: big.NewInt(5), MaxTotalCost: big.NewInt(100000), ExpectedNonce: &nonce}
	t.Run("wrong chain", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(5), Nonce: 4, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(4), Gas: 21000, To: &to, Value: big.NewInt(1)})
		if _, err := ValidateUnsigned(marshal(tx), rules); err == nil {
			t.Fatal("wrong chain accepted")
		}
	})
	t.Run("wrong nonce", func(t *testing.T) {
		other := rules
		expected := uint64(5)
		other.ExpectedNonce = &expected
		if _, err := ValidateUnsigned(marshal(base), other); err == nil {
			t.Fatal("wrong nonce accepted")
		}
	})
	t.Run("destination", func(t *testing.T) {
		other := rules
		other.AllowedDestinations = nil
		if _, err := ValidateUnsigned(marshal(base), other); err == nil {
			t.Fatal("destination accepted")
		}
	})
	t.Run("fee ceiling", func(t *testing.T) {
		other := rules
		other.MaxGasPrice = big.NewInt(2)
		if _, err := ValidateUnsigned(marshal(base), other); err == nil {
			t.Fatal("fee cap accepted")
		}
	})
	t.Run("total cost", func(t *testing.T) {
		other := rules
		other.MaxTotalCost = big.NewInt(2)
		if _, err := ValidateUnsigned(marshal(base), other); err == nil {
			t.Fatal("excess total cost accepted")
		}
	})
	t.Run("unapproved calldata", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 4, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(4), Gas: 30000, To: &to, Value: big.NewInt(1), Data: []byte{1, 2, 3, 4}})
		rules.MaxTotalCost = big.NewInt(200000)
		if _, err := ValidateUnsigned(marshal(tx), rules); err == nil {
			t.Fatal("call without calldata policy accepted")
		}
		other := rules
		other.Calldata = denyCall{}
		if _, err := ValidateUnsigned(marshal(tx), other); err == nil {
			t.Fatal("denied calldata accepted")
		}
		other.Calldata = allowCall{}
		if _, err := ValidateUnsigned(marshal(tx), other); err != nil {
			t.Fatalf("allowed call rejected: %v", err)
		}
	})
	t.Run("contract creation", func(t *testing.T) {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 4, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(4), Gas: 30000, Value: big.NewInt(1)})
		if _, err := ValidateUnsigned(marshal(tx), rules); err == nil {
			t.Fatal("contract creation accepted")
		}
	})
	t.Run("nonce policy required", func(t *testing.T) {
		other := rules
		other.ExpectedNonce = nil
		if _, err := ValidateUnsigned(marshal(base), other); err == nil {
			t.Fatal("missing nonce reservation accepted")
		}
	})
}
