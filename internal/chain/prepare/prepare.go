// Package prepare links chain-specific transaction decoding to the shared
// approval policy. Signers should call these functions before starting TSS.
package prepare

import (
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/purplecity/bnb_chain_tss/internal/chain/evm"
	"github.com/purplecity/bnb_chain_tss/internal/chain/tron"
	"github.com/purplecity/bnb_chain_tss/internal/policy"
)

func EVM(intent policy.Intent, rules policy.Rules, chainRules evm.Rules, now time.Time, approvals policy.ApprovalVerifier) (evm.UnsignedTransaction, error) {
	if intent.Chain != "evm" {
		return evm.UnsignedTransaction{}, errors.New("intent chain is not EVM")
	}
	prepared, err := evm.ValidateUnsigned(intent.UnsignedTx, chainRules)
	if err != nil {
		return evm.UnsignedTransaction{}, err
	}
	if intent.Network != rules.Network || rules.Chain != "evm" || intent.To == "" || !strings.EqualFold(intent.To, prepared.Transaction.To().Hex()) || intent.Value == nil || intent.Value.Cmp(prepared.Transaction.Value()) != 0 {
		return evm.UnsignedTransaction{}, errors.New("signing intent fields do not match decoded EVM transaction")
	}
	if err := policy.Validate(intent, rules, now, approvals); err != nil {
		return evm.UnsignedTransaction{}, err
	}
	return prepared, nil
}

func TRON(intent policy.Intent, rules policy.Rules, chainRules tron.Rules, now time.Time, approvals policy.ApprovalVerifier) (tron.UnsignedTransaction, error) {
	if intent.Chain != "tron" {
		return tron.UnsignedTransaction{}, errors.New("intent chain is not TRON")
	}
	prepared, err := tron.ValidateUnsigned(intent.UnsignedTx, chainRules, now)
	if err != nil {
		return tron.UnsignedTransaction{}, err
	}
	to := common.Bytes2Hex(prepared.Destination)
	value := big.NewInt(prepared.Value)
	if intent.Network != prepared.Network || rules.Chain != "tron" || intent.To == "" || !strings.EqualFold(strings.TrimPrefix(intent.To, "0x"), to) || intent.Value == nil || intent.Value.Cmp(value) != 0 {
		return tron.UnsignedTransaction{}, errors.New("signing intent fields do not match decoded TRON transaction")
	}
	if err := policy.Validate(intent, rules, now, approvals); err != nil {
		return tron.UnsignedTransaction{}, err
	}
	return prepared, nil
}
