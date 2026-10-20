package sign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
)

var safeWalletID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

type Wallet struct {
	Meta     derive.WalletMeta
	Share    keygen.LocalPartySaveData
	PartyIDs tss.SortedPartyIDs
	LocalID  string
}

func LoadWallet(walletDir, walletID, nodeID string) (*Wallet, error) {
	if !safeWalletID.MatchString(walletID) {
		return nil, errors.New("invalid wallet ID")
	}
	base := filepath.Join(walletDir, walletID)
	metaBytes, err := os.ReadFile(filepath.Join(base, "wallet.json"))
	if err != nil {
		return nil, fmt.Errorf("read wallet metadata: %w", err)
	}
	var meta derive.WalletMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("decode wallet metadata: %w", err)
	}
	if meta.Version != 1 || meta.WalletID != walletID || len(meta.PartyIDs) != 3 {
		return nil, errors.New("wallet metadata version, ID or roster is invalid")
	}
	shareBytes, err := os.ReadFile(filepath.Join(base, "share.json"))
	if err != nil {
		return nil, fmt.Errorf("read local wallet share: %w", err)
	}
	var share keygen.LocalPartySaveData
	if err := json.Unmarshal(shareBytes, &share); err != nil {
		return nil, fmt.Errorf("decode local wallet share: %w", err)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(meta.PartyIDs))
	for i, party := range meta.PartyIDs {
		if !safeWalletID.MatchString(party.ID) {
			return nil, errors.New("invalid party ID in wallet metadata")
		}
		key, ok := new(big.Int).SetString(party.Key, 10)
		if !ok || key.Sign() <= 0 {
			return nil, fmt.Errorf("invalid party key for %s", party.ID)
		}
		partyIDs[i] = tss.NewPartyID(party.ID, party.ID, key)
	}
	sorted := tss.SortPartyIDs(partyIDs)
	if len(share.Ks) != 3 || share.ShareID == nil || share.Xi == nil || share.ECDSAPub == nil || !share.LocalPreParams.ValidateWithProof() {
		return nil, errors.New("LocalPartySaveData is incomplete or lacks valid local pre-parameters")
	}
	for i, id := range sorted {
		if i >= len(share.Ks) || share.Ks[i] == nil || share.Ks[i].Cmp(id.KeyInt()) != 0 {
			return nil, errors.New("wallet roster does not match LocalPartySaveData.Ks")
		}
	}
	if share.ECDSAPub == nil || !share.ECDSAPub.ValidateBasic() {
		return nil, errors.New("invalid root public key in share")
	}
	if meta.RootPub == "" {
		return nil, errors.New("root public key is missing from wallet metadata")
	}
	rootBytes, err := hex.DecodeString(meta.RootPub)
	if err != nil || len(rootBytes) != 33 {
		return nil, errors.New("invalid root public key in wallet metadata")
	}
	chainCode, err := hex.DecodeString(meta.ChainCode)
	if err != nil || len(chainCode) != 32 {
		return nil, errors.New("invalid chain code in wallet metadata")
	}
	rootPub, err := gethcrypto.DecompressPubkey(rootBytes)
	if err != nil || share.ECDSAPub.X().Cmp(rootPub.X) != 0 || share.ECDSAPub.Y().Cmp(rootPub.Y) != 0 {
		return nil, errors.New("wallet metadata root public key does not match share")
	}
	if localIDIndex(meta.PartyIDs, nodeID) < 0 {
		return nil, fmt.Errorf("node %s is not in this wallet committee", nodeID)
	}
	localKey, _ := new(big.Int).SetString(meta.PartyIDs[localIDIndex(meta.PartyIDs, nodeID)].Key, 10)
	if share.ShareID.Cmp(localKey) != 0 {
		return nil, errors.New("share file belongs to a different signer node")
	}
	if len(share.BigXj) != 3 || len(share.PaillierPKs) != 3 || len(share.NTildej) != 3 || len(share.H1j) != 3 || len(share.H2j) != 3 {
		return nil, errors.New("LocalPartySaveData public parameter arrays must each have three entries")
	}
	// tss-lib's own keygen fixture loader reattaches the active curve after
	// decoding ECPoint JSON. Do the same for persisted shares before passing
	// them to signing, so all points use the exact curve instance in Parameters.
	for i, point := range share.BigXj {
		if point == nil {
			return nil, fmt.Errorf("LocalPartySaveData BigXj[%d] is missing", i)
		}
		point.SetCurve(tss.S256())
	}
	share.ECDSAPub.SetCurve(tss.S256())
	return &Wallet{Meta: meta, Share: share, PartyIDs: sorted, LocalID: nodeID}, nil
}

func localIDIndex(roster []derive.Party, nodeID string) int {
	for i := range roster {
		if roster[i].ID == nodeID {
			return i
		}
	}
	return -1
}

func (w *Wallet) LocalPartyID() (*tss.PartyID, error) {
	for _, id := range w.PartyIDs {
		if id.Id == w.LocalID {
			return id, nil
		}
	}
	return nil, errors.New("local party ID is not in roster")
}

func (w *Wallet) PublicKeyMatchesMetadata() bool {
	point := w.Share.ECDSAPub
	if point == nil {
		return false
	}
	return hex.EncodeToString(gethcrypto.CompressPubkey(&ecdsa.PublicKey{Curve: point.Curve(), X: point.X(), Y: point.Y()})) == w.Meta.RootPub
}
