package tron

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type blockOK struct{}

func (blockOK) VerifyReferenceBlock(string, []byte, int64, []byte) error { return nil }

type blockFail struct{}

func (blockFail) VerifyReferenceBlock(string, []byte, int64, []byte) error {
	return errors.New("wrong chain block")
}

type contractOK struct{}

func (contractOK) ValidateTrigger([]byte, int64, int64, int64, []byte) error { return nil }

func TestTransferTransactionDigestAndSignature(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	owner := tronAddress(&key.PublicKey)
	to := []byte{0x41, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	now := time.Now().Truncate(time.Millisecond)
	tx := transferTx(owner, to, now)
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	rules := baseRules(owner, to)
	validated, err := ValidateUnsigned(encoded, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := crypto.Sign(validated.Digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := AttachSignature(validated, tssadapter.Signature{R: new(big.Int).SetBytes(compact[:32]), S: new(big.Int).SetBytes(compact[32:64]), RecoveryID: compact[64]})
	if err != nil {
		t.Fatal(err)
	}
	signed := new(core.Transaction)
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		t.Fatal(err)
	}
	if len(signed.GetSignature()) != 1 || len(signed.GetSignature()[0]) != 65 {
		t.Fatalf("expected one canonical 65-byte signature, got %d", len(signed.GetSignature()))
	}
	revalidated, err := ValidateUnsigned(encoded, rules, now)
	if err != nil {
		t.Fatal(err)
	}
	if revalidated.Digest != validated.Digest {
		t.Fatal("digest is not deterministic")
	}
}

func TestTronPolicyRejectsUnsafeTransactions(t *testing.T) {
	owner := []byte{0x41, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}
	to := []byte{0x41, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	now := time.Now().Truncate(time.Millisecond)
	encoded := func(tx *core.Transaction) []byte {
		b, err := (proto.MarshalOptions{Deterministic: true}).Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("wrong reference block", func(t *testing.T) {
		r := baseRules(owner, to)
		r.ReferenceBlocks = blockFail{}
		if _, err := ValidateUnsigned(encoded(transferTx(owner, to, now)), r, now); err == nil {
			t.Fatal("wrong network block accepted")
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		bad := append([]byte(nil), owner...)
		bad[20]++
		if _, err := ValidateUnsigned(encoded(transferTx(bad, to, now)), baseRules(owner, to), now); err == nil {
			t.Fatal("wrong owner accepted")
		}
	})
	t.Run("destination", func(t *testing.T) {
		if _, err := ValidateUnsigned(encoded(transferTx(owner, to, now)), baseRules(owner, owner), now); err == nil {
			t.Fatal("unknown recipient accepted")
		}
	})
	t.Run("amount", func(t *testing.T) {
		tx := transferTx(owner, to, now)
		var transfer core.TransferContract
		if err := tx.RawData.Contract[0].Parameter.UnmarshalTo(&transfer); err != nil {
			t.Fatal(err)
		}
		transfer.Amount = 101
		tx.RawData.Contract[0].Parameter, _ = anypb.New(&transfer)
		if _, err := ValidateUnsigned(encoded(tx), baseRules(owner, to), now); err == nil {
			t.Fatal("amount above limit accepted")
		}
	})
	t.Run("expired", func(t *testing.T) {
		tx := transferTx(owner, to, now)
		tx.RawData.Expiration = now.Add(-time.Second).UnixMilli()
		if _, err := ValidateUnsigned(encoded(tx), baseRules(owner, to), now); err == nil {
			t.Fatal("expired transaction accepted")
		}
	})
	t.Run("already signed", func(t *testing.T) {
		tx := transferTx(owner, to, now)
		tx.Signature = [][]byte{{1}}
		if _, err := ValidateUnsigned(encoded(tx), baseRules(owner, to), now); err == nil {
			t.Fatal("already signed transaction accepted")
		}
	})
	t.Run("unsupported contract", func(t *testing.T) {
		tx := transferTx(owner, to, now)
		tx.RawData.Contract[0].Type = core.Transaction_Contract_AccountCreateContract
		if _, err := ValidateUnsigned(encoded(tx), baseRules(owner, to), now); err == nil {
			t.Fatal("unsupported contract accepted")
		}
	})
	t.Run("missing reference verifier", func(t *testing.T) {
		r := baseRules(owner, to)
		r.ReferenceBlocks = nil
		if _, err := ValidateUnsigned(encoded(transferTx(owner, to, now)), r, now); err == nil {
			t.Fatal("missing reference verifier accepted")
		}
	})
}

func TestTriggerRequiresContractPolicy(t *testing.T) {
	owner := []byte{0x41, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}
	contract := []byte{0x41, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	now := time.Now().Truncate(time.Millisecond)
	call := &core.TriggerSmartContract{OwnerAddress: owner, ContractAddress: contract, Data: []byte{1, 2, 3, 4}}
	anyCall, err := anypb.New(call)
	if err != nil {
		t.Fatal(err)
	}
	tx := &core.Transaction{RawData: &core.TransactionRaw{RefBlockBytes: []byte{1, 2}, RefBlockHash: make([]byte, 8), Expiration: now.Add(time.Minute).UnixMilli(), Timestamp: now.UnixMilli(), FeeLimit: 100, Contract: []*core.Transaction_Contract{{Type: core.Transaction_Contract_TriggerSmartContract, Parameter: anyCall, PermissionId: 2}}}}
	rules := baseRules(owner, contract)
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateUnsigned(raw, rules, now); err == nil {
		t.Fatal("trigger without explicit call policy accepted")
	}
	rules.ContractCalls = contractOK{}
	if _, err := ValidateUnsigned(raw, rules, now); err != nil {
		t.Fatalf("approved trigger rejected: %v", err)
	}
}

func transferTx(owner, to []byte, now time.Time) *core.Transaction {
	payload, _ := anypb.New(&core.TransferContract{OwnerAddress: owner, ToAddress: to, Amount: 50})
	return &core.Transaction{RawData: &core.TransactionRaw{RefBlockBytes: []byte{1, 2}, RefBlockNum: 123, RefBlockHash: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Expiration: now.Add(time.Minute).UnixMilli(), Timestamp: now.UnixMilli(), Contract: []*core.Transaction_Contract{{Type: core.Transaction_Contract_TransferContract, Parameter: payload, PermissionId: 2}}}}
}

func baseRules(owner, to []byte) Rules {
	return Rules{Network: "nile", ExpectedOwner: append([]byte(nil), owner...), AllowedRecipients: map[string]struct{}{fmt.Sprintf("%x", to): {}}, MaxTransferAmount: 100, MaxFeeLimit: 1_000_000, ExpectedPermissionID: 2, MaxTransactionLifetime: 5 * time.Minute, MaxTimestampAge: 30 * time.Second, MaxMemoBytes: 128, MaxEncodedBytes: 64 * 1024, ReferenceBlocks: blockOK{}}
}

func tronAddress(pub *ecdsa.PublicKey) []byte {
	encoded := crypto.FromECDSAPub(pub)
	address, _ := AddressForPublicKey(encoded)
	return address
}
