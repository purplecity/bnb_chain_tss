// Package tron validates canonical TRON transactions and encodes signatures
// using the java-tron 65-byte R || S || recovery format.
package tron

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
	"google.golang.org/protobuf/proto"
)

type ReferenceBlockVerifier interface {
	VerifyReferenceBlock(network string, refBlockBytes []byte, refBlockNum int64, refBlockHash []byte) error
}

type ContractCallPolicy interface {
	ValidateTrigger(contractAddress []byte, callValue int64, callTokenValue, tokenID int64, data []byte) error
}

type Rules struct {
	Network                string
	ExpectedOwner          []byte              // 21-byte TRON address including 0x41 prefix
	AllowedRecipients      map[string]struct{} // lowercase hex of 21-byte address
	MaxTransferAmount      int64
	MaxFeeLimit            int64
	ExpectedPermissionID   int32
	MaxTransactionLifetime time.Duration
	MaxTimestampAge        time.Duration
	MaxMemoBytes           int
	MaxEncodedBytes        int
	ReferenceBlocks        ReferenceBlockVerifier
	ContractCalls          ContractCallPolicy
}

type UnsignedTransaction struct {
	Transaction *core.Transaction
	RawData     []byte
	Digest      [32]byte
	Network     string
	Owner       []byte
	Destination []byte
	Value       int64
}

func ValidateUnsigned(encoded []byte, rules Rules, now time.Time) (UnsignedTransaction, error) {
	if len(encoded) == 0 || (rules.MaxEncodedBytes > 0 && len(encoded) > rules.MaxEncodedBytes) {
		return UnsignedTransaction{}, errors.New("TRON transaction encoding is empty or too large")
	}
	if rules.Network == "" || !validAddress(rules.ExpectedOwner) || len(rules.AllowedRecipients) == 0 || rules.MaxTransferAmount <= 0 || rules.MaxFeeLimit < 0 || rules.MaxTransactionLifetime <= 0 || rules.MaxTimestampAge <= 0 || rules.ReferenceBlocks == nil {
		return UnsignedTransaction{}, errors.New("incomplete TRON signing policy")
	}
	tx := new(core.Transaction)
	if err := proto.Unmarshal(encoded, tx); err != nil {
		return UnsignedTransaction{}, fmt.Errorf("decode TRON transaction: %w", err)
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(tx)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return UnsignedTransaction{}, errors.New("TRON transaction encoding is not canonical")
	}
	if len(tx.Signature) != 0 || len(tx.PqAuthSig) != 0 || len(tx.Ret) != 0 {
		return UnsignedTransaction{}, errors.New("TRON transaction is already signed or has execution results")
	}
	if len(tx.ProtoReflect().GetUnknown()) != 0 {
		return UnsignedTransaction{}, errors.New("TRON transaction contains unknown fields")
	}
	raw := tx.GetRawData()
	if raw == nil || len(raw.GetContract()) != 1 || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return UnsignedTransaction{}, errors.New("TRON transaction must have raw data and exactly one known contract")
	}
	if len(raw.GetRefBlockBytes()) != 2 || len(raw.GetRefBlockHash()) != 8 {
		return UnsignedTransaction{}, errors.New("TRON reference block fields have invalid lengths")
	}
	if raw.GetExpiration() <= now.UnixMilli() || time.UnixMilli(raw.GetExpiration()).After(now.Add(rules.MaxTransactionLifetime)) {
		return UnsignedTransaction{}, errors.New("TRON transaction is expired or has excessive lifetime")
	}
	if raw.GetTimestamp() <= 0 || time.UnixMilli(raw.GetTimestamp()).Before(now.Add(-rules.MaxTimestampAge)) || time.UnixMilli(raw.GetTimestamp()).After(now.Add(rules.MaxTimestampAge)) {
		return UnsignedTransaction{}, errors.New("TRON transaction timestamp is outside policy window")
	}
	if raw.GetExpiration() <= raw.GetTimestamp() {
		return UnsignedTransaction{}, errors.New("TRON expiration must be after transaction timestamp")
	}
	if len(raw.GetData()) > rules.MaxMemoBytes && rules.MaxMemoBytes >= 0 {
		return UnsignedTransaction{}, errors.New("TRON memo exceeds policy")
	}
	if raw.GetFeeLimit() < 0 || raw.GetFeeLimit() > rules.MaxFeeLimit {
		return UnsignedTransaction{}, errors.New("TRON fee_limit exceeds policy")
	}
	if err := rules.ReferenceBlocks.VerifyReferenceBlock(rules.Network, raw.GetRefBlockBytes(), raw.GetRefBlockNum(), raw.GetRefBlockHash()); err != nil {
		return UnsignedTransaction{}, fmt.Errorf("TRON reference block rejected: %w", err)
	}
	contract := raw.GetContract()[0]
	if contract == nil || contract.GetParameter() == nil || len(contract.ProtoReflect().GetUnknown()) != 0 {
		return UnsignedTransaction{}, errors.New("TRON contract is malformed")
	}
	var owner []byte
	var destination []byte
	var value int64
	switch contract.GetType() {
	case core.Transaction_Contract_TransferContract:
		transfer := new(core.TransferContract)
		if err := contract.GetParameter().UnmarshalTo(transfer); err != nil {
			return UnsignedTransaction{}, fmt.Errorf("decode TRON transfer contract: %w", err)
		}
		if len(transfer.ProtoReflect().GetUnknown()) != 0 {
			return UnsignedTransaction{}, errors.New("TRON transfer contract has unknown fields")
		}
		owner = transfer.GetOwnerAddress()
		destination = transfer.GetToAddress()
		value = transfer.GetAmount()
		if transfer.GetAmount() <= 0 || transfer.GetAmount() > rules.MaxTransferAmount {
			return UnsignedTransaction{}, errors.New("TRON transfer amount exceeds policy")
		}
		if !allowedAddress(transfer.GetToAddress(), rules.AllowedRecipients) {
			return UnsignedTransaction{}, errors.New("TRON recipient is not allowed")
		}
	case core.Transaction_Contract_TriggerSmartContract:
		call := new(core.TriggerSmartContract)
		if err := contract.GetParameter().UnmarshalTo(call); err != nil {
			return UnsignedTransaction{}, fmt.Errorf("decode TRON trigger contract: %w", err)
		}
		if len(call.ProtoReflect().GetUnknown()) != 0 {
			return UnsignedTransaction{}, errors.New("TRON trigger contract has unknown fields")
		}
		owner = call.GetOwnerAddress()
		destination = call.GetContractAddress()
		value = call.GetCallValue()
		if !validAddress(call.GetContractAddress()) || rules.ContractCalls == nil {
			return UnsignedTransaction{}, errors.New("TRON contract call requires an explicit policy")
		}
		if call.GetCallValue() < 0 || call.GetCallValue() > rules.MaxTransferAmount || call.GetCallTokenValue() < 0 {
			return UnsignedTransaction{}, errors.New("TRON contract call value exceeds policy")
		}
		if err := rules.ContractCalls.ValidateTrigger(call.GetContractAddress(), call.GetCallValue(), call.GetCallTokenValue(), call.GetTokenId(), call.GetData()); err != nil {
			return UnsignedTransaction{}, fmt.Errorf("TRON contract call rejected: %w", err)
		}
	default:
		return UnsignedTransaction{}, fmt.Errorf("TRON contract type %s is not allowed", contract.GetType())
	}
	if !bytes.Equal(owner, rules.ExpectedOwner) {
		return UnsignedTransaction{}, errors.New("TRON transaction owner does not match wallet address")
	}
	if contract.GetPermissionId() != rules.ExpectedPermissionID {
		return UnsignedTransaction{}, errors.New("TRON permission ID does not match policy")
	}
	if len(raw.GetAuths()) != 0 || len(raw.GetScripts()) != 0 {
		return UnsignedTransaction{}, errors.New("TRON transaction contains unsupported authorization fields")
	}
	rawData, err := (proto.MarshalOptions{Deterministic: true}).Marshal(raw)
	if err != nil {
		return UnsignedTransaction{}, fmt.Errorf("encode TRON raw_data: %w", err)
	}
	digest := sha256.Sum256(rawData)
	return UnsignedTransaction{Transaction: tx, RawData: rawData, Digest: digest, Network: rules.Network, Owner: append([]byte(nil), owner...), Destination: append([]byte(nil), destination...), Value: value}, nil
}

func AttachSignature(unsigned UnsignedTransaction, sig tssadapter.Signature) ([]byte, error) {
	if unsigned.Transaction == nil || unsigned.Network == "" || !validAddress(unsigned.Owner) || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.RecoveryID > 1 {
		return nil, errors.New("invalid validated TRON transaction or signature")
	}
	if !crypto.ValidateSignatureValues(sig.RecoveryID, sig.R, sig.S, true) {
		return nil, errors.New("TRON signature values are invalid or not low-S")
	}
	rawData, err := (proto.MarshalOptions{Deterministic: true}).Marshal(unsigned.Transaction.GetRawData())
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(rawData)
	if digest != unsigned.Digest || !bytes.Equal(rawData, unsigned.RawData) {
		return nil, errors.New("TRON transaction changed after policy validation")
	}
	cloned := proto.Clone(unsigned.Transaction).(*core.Transaction)
	signature := make([]byte, 65)
	sig.R.FillBytes(signature[:32])
	sig.S.FillBytes(signature[32:64])
	signature[64] = sig.RecoveryID
	cloned.Signature = append(cloned.Signature, signature)
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("encode signed TRON transaction: %w", err)
	}
	recovered, err := crypto.Ecrecover(unsigned.Digest[:], signature)
	if err != nil || len(recovered) != 65 {
		return nil, errors.New("recover TRON signature public key failed")
	}
	address := append([]byte{0x41}, crypto.Keccak256(recovered[1:])[12:]...)
	if !bytes.Equal(address, unsigned.Owner) {
		return nil, errors.New("TRON signature recovered an unexpected owner")
	}
	return encoded, nil
}

func validAddress(address []byte) bool { return len(address) == 21 && address[0] == 0x41 }

func allowedAddress(address []byte, allowed map[string]struct{}) bool {
	if !validAddress(address) {
		return false
	}
	_, ok := allowed[fmt.Sprintf("%x", address)]
	return ok
}

func AddressForPublicKey(pub []byte) ([]byte, error) {
	if len(pub) != 65 || pub[0] != 4 {
		return nil, errors.New("expected uncompressed secp256k1 public key")
	}
	return append([]byte{0x41}, crypto.Keccak256(pub[1:])[12:]...), nil
}
