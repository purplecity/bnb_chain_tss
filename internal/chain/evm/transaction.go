// Package evm validates and encodes EVM EOA transactions before and after
// threshold signing. It never decides policy for contract calldata by itself.
package evm

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
)

type CalldataPolicy interface {
	ValidateCall(to common.Address, value *big.Int, data []byte) error
}

type Rules struct {
	ChainID             *big.Int
	ExpectedSender      common.Address
	AllowedDestinations map[common.Address]struct{}
	MaxValue            *big.Int
	MaxGas              uint64
	MaxGasPrice         *big.Int
	MaxTotalCost        *big.Int
	Calldata            CalldataPolicy
	MaxEncodedBytes     int
	ExpectedNonce       *uint64
}

type UnsignedTransaction struct {
	Transaction *types.Transaction
	Signer      types.Signer
	Digest      [32]byte
	Sender      common.Address
}

func ValidateUnsigned(raw []byte, rules Rules) (UnsignedTransaction, error) {
	if len(raw) == 0 || (rules.MaxEncodedBytes > 0 && len(raw) > rules.MaxEncodedBytes) {
		return UnsignedTransaction{}, errors.New("transaction encoding is empty or exceeds the size limit")
	}
	if rules.ChainID == nil || rules.ChainID.Sign() <= 0 || rules.ExpectedSender == (common.Address{}) || rules.MaxValue == nil || rules.MaxValue.Sign() < 0 || rules.MaxGas == 0 || rules.MaxGasPrice == nil || rules.MaxGasPrice.Sign() < 0 || rules.MaxTotalCost == nil || rules.MaxTotalCost.Sign() < 0 || rules.ExpectedNonce == nil {
		return UnsignedTransaction{}, errors.New("incomplete EVM signing policy")
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return UnsignedTransaction{}, fmt.Errorf("decode EVM transaction: %w", err)
	}
	canonical, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(raw, canonical) {
		return UnsignedTransaction{}, errors.New("EVM transaction encoding is not canonical")
	}
	if tx.Type() != types.LegacyTxType && tx.Type() != types.AccessListTxType && tx.Type() != types.DynamicFeeTxType {
		return UnsignedTransaction{}, fmt.Errorf("unsupported EVM transaction type %d", tx.Type())
	}
	if tx.To() == nil {
		return UnsignedTransaction{}, errors.New("contract creation transactions are disabled by this policy")
	}
	if tx.Type() != types.LegacyTxType && tx.ChainId().Cmp(rules.ChainID) != 0 {
		return UnsignedTransaction{}, errors.New("EVM chain ID does not match configured network")
	}
	if tx.Nonce() != *rules.ExpectedNonce {
		return UnsignedTransaction{}, errors.New("EVM nonce does not match reserved nonce")
	}
	if tx.Value() == nil || tx.Value().Sign() < 0 || tx.Value().Cmp(rules.MaxValue) > 0 {
		return UnsignedTransaction{}, errors.New("EVM value exceeds policy")
	}
	if tx.Gas() == 0 || tx.Gas() > rules.MaxGas {
		return UnsignedTransaction{}, errors.New("EVM gas limit exceeds policy")
	}
	if tx.GasPrice().Cmp(rules.MaxGasPrice) > 0 {
		return UnsignedTransaction{}, errors.New("EVM gas price or fee cap exceeds policy")
	}
	if _, ok := rules.AllowedDestinations[*tx.To()]; !ok {
		return UnsignedTransaction{}, errors.New("EVM destination is not allowed")
	}
	if len(tx.Data()) > 0 {
		if rules.Calldata == nil {
			return UnsignedTransaction{}, errors.New("contract calldata requires an explicit policy")
		}
		if err := rules.Calldata.ValidateCall(*tx.To(), tx.Value(), tx.Data()); err != nil {
			return UnsignedTransaction{}, fmt.Errorf("EVM calldata rejected: %w", err)
		}
	}
	maxCost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasPrice())
	maxCost.Add(maxCost, tx.Value())
	if maxCost.Cmp(rules.MaxTotalCost) > 0 {
		return UnsignedTransaction{}, errors.New("EVM maximum total cost exceeds policy")
	}
	if v, r, s := tx.RawSignatureValues(); (v != nil && v.Sign() != 0) || (r != nil && r.Sign() != 0) || (s != nil && s.Sign() != 0) {
		return UnsignedTransaction{}, errors.New("transaction is already signed")
	}
	signer := types.LatestSignerForChainID(rules.ChainID)
	digest := signer.Hash(tx)
	var digestBytes [32]byte
	copy(digestBytes[:], digest[:])
	return UnsignedTransaction{Transaction: tx, Signer: signer, Digest: digestBytes, Sender: rules.ExpectedSender}, nil
}

func AttachSignature(unsigned UnsignedTransaction, sig tssadapter.Signature, expectedSender common.Address) ([]byte, error) {
	if unsigned.Transaction == nil || unsigned.Signer == nil {
		return nil, errors.New("missing validated EVM transaction")
	}
	if got := unsigned.Signer.Hash(unsigned.Transaction); !bytes.Equal(got[:], unsigned.Digest[:]) {
		return nil, errors.New("EVM transaction changed after policy validation")
	}
	if len(unsigned.Digest) != 32 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.RecoveryID > 1 {
		return nil, errors.New("invalid EVM signature components")
	}
	if !crypto.ValidateSignatureValues(sig.RecoveryID, sig.R, sig.S, true) {
		return nil, errors.New("EVM signature values are invalid or not low-S")
	}
	compact := make([]byte, crypto.SignatureLength)
	sig.R.FillBytes(compact[:32])
	sig.S.FillBytes(compact[32:64])
	compact[64] = sig.RecoveryID
	signed, err := unsigned.Transaction.WithSignature(unsigned.Signer, compact)
	if err != nil {
		return nil, fmt.Errorf("attach EVM signature: %w", err)
	}
	from, err := types.Sender(unsigned.Signer, signed)
	if err != nil {
		return nil, fmt.Errorf("recover signed EVM sender: %w", err)
	}
	if from != expectedSender || from != unsigned.Sender {
		return nil, errors.New("EVM signature recovered an unexpected sender")
	}
	return signed.MarshalBinary()
}

func AddressFromPublicKey(pub *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pub)
}
