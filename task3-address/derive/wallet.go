package derive

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v4/crypto/ckd"
	"github.com/bnb-chain/tss-lib/v4/tss"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const HardenedStart uint32 = 1 << 31

// WalletMeta is public derivation metadata distributed with every signer share.
// ChainCode is not a private signing key, but it reveals the wallet's public
// address tree and must be protected if address privacy matters.
type WalletMeta struct {
	Version   int     `json:"version"`
	WalletID  string  `json:"wallet_id"`
	RootPub   string  `json:"root_public_key_compressed"`
	ChainCode string  `json:"chain_code"`
	PartyIDs  []Party `json:"party_ids"`
}

type Party struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type Result struct {
	WalletID  string `json:"wallet_id"`
	SiteID    uint32 `json:"site_id"`
	Index     uint32 `json:"index"`
	Path      string `json:"path"`
	PublicKey string `json:"child_public_key_uncompressed"`
	EVM       string `json:"evm_address"`
	TRON      string `json:"tron_address"`
}

// Derive returns the child public key and addresses for m/siteID/index.
// Both path components are intentionally non-hardened so a public derivation
// service can generate deposit addresses without receiving signing shares.
func Derive(meta WalletMeta, siteID, index uint32) (Result, *big.Int, error) {
	if siteID >= HardenedStart || index >= HardenedStart {
		return Result{}, nil, fmt.Errorf("site_id and index must be below %d (non-hardened)", HardenedStart)
	}
	rootBytes, err := hex.DecodeString(meta.RootPub)
	if err != nil || len(rootBytes) != 33 {
		return Result{}, nil, errors.New("root_public_key_compressed must be 33-byte hex")
	}
	chainCode, err := hex.DecodeString(meta.ChainCode)
	if err != nil || len(chainCode) != 32 {
		return Result{}, nil, errors.New("chain_code must be 32-byte hex")
	}
	rootPub, err := gethcrypto.DecompressPubkey(rootBytes)
	if err != nil {
		return Result{}, nil, fmt.Errorf("invalid root public key: %w", err)
	}
	curve := tss.S256()
	parent := &ckd.ExtendedKey{
		PublicKey:  *rootPub,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
		ParentFP:   []byte{0, 0, 0, 0},
		Version:    []byte{0x04, 0x88, 0xb2, 0x1e},
	}
	tweak, child, err := ckd.DeriveChildKeyFromHierarchy([]uint32{siteID, index}, parent, curve.Params().N, curve)
	if err != nil {
		return Result{}, nil, fmt.Errorf("derive child public key: %w", err)
	}
	childPub := &child.PublicKey
	pubUncompressed := gethcrypto.FromECDSAPub(childPub)
	evm := gethcrypto.PubkeyToAddress(*childPub)
	tronPayload := gethcrypto.Keccak256(pubUncompressed[1:])[12:]
	tron := base58.CheckEncode(tronPayload, 0x41)

	return Result{
		WalletID:  meta.WalletID,
		SiteID:    siteID,
		Index:     index,
		Path:      fmt.Sprintf("m/%d/%d", siteID, index),
		PublicKey: hex.EncodeToString(pubUncompressed),
		EVM:       evm.Hex(),
		TRON:      tron,
	}, tweak, nil
}

// ValidateAddressPair is useful to signer/gateway callers that need to reject
// corrupted metadata before using a derived path.
func ValidateAddressPair(meta WalletMeta, siteID, index uint32, expectedEVM, expectedTRON string) error {
	got, _, err := Derive(meta, siteID, index)
	if err != nil {
		return err
	}
	if common.HexToAddress(got.EVM) != common.HexToAddress(expectedEVM) || got.TRON != expectedTRON {
		return errors.New("derived address does not match expected address")
	}
	return nil
}

func ParsePrivateScalar(hexKey string) (*big.Int, error) {
	if len(hexKey) != 64 {
		return nil, errors.New("private key must be exactly 64 hex characters without 0x prefix")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("private key is not valid hex")
	}
	d := new(big.Int).SetBytes(b)
	n := tss.S256().Params().N
	if d.Sign() == 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("private key scalar is outside secp256k1 range")
	}
	return d, nil
}

func EVMAddress(pub *ecdsa.PublicKey) string { return gethcrypto.PubkeyToAddress(*pub).Hex() }
