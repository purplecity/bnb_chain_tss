package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"

	tsscrypto "github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/tss"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
)

const dkgTimeout = 20 * time.Minute

var walletIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// GenerateWalletShares uses tss-lib's Feldman VSS directly with the supplied
// private scalar, then assembles the save-data fields consumed by its ECDSA
// signing protocol. Each signer's Paillier and safe-prime pre-parameters are
// generated with tss-lib's keygen pre-parameter generator.
func GenerateWalletShares(ctx context.Context, walletID string, target *big.Int) ([]keygen.LocalPartySaveData, derive.WalletMeta, error) {
	if !walletIDPattern.MatchString(walletID) {
		return nil, derive.WalletMeta{}, errors.New("wallet ID must match [A-Za-z0-9_-]{1,80}")
	}
	if target == nil || target.Sign() <= 0 || target.Cmp(tss.S256().Params().N) >= 0 {
		return nil, derive.WalletMeta{}, errors.New("private key scalar is outside secp256k1 range")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		tss.NewPartyID("node-1", "node-1", big.NewInt(1)),
		tss.NewPartyID("node-2", "node-2", big.NewInt(2)),
		tss.NewPartyID("node-3", "node-3", big.NewInt(3)),
	})
	indexes := make([]*big.Int, len(ids))
	for i, id := range ids {
		indexes[i] = new(big.Int).SetBytes(id.Key)
	}
	commitments, shares, err := vss.Create(tss.S256(), 1, new(big.Int).Set(target), indexes, rand.Reader)
	if err != nil {
		return nil, derive.WalletMeta{}, fmt.Errorf("create 2-of-3 VSS shares: %w", err)
	}
	for i, share := range shares {
		if !share.Verify(tss.S256(), 1, commitments) {
			return nil, derive.WalletMeta{}, fmt.Errorf("tss-lib VSS share %d failed Feldman verification", i+1)
		}
	}
	preParams, err := generateSignerPreParams(ctx, len(ids))
	if err != nil {
		return nil, derive.WalletMeta{}, err
	}
	keys, err := buildLocalSaveData(ids, shares, commitments, preParams)
	if err != nil {
		return nil, derive.WalletMeta{}, err
	}
	rootPoint := commitments[0]
	pub := &ecdsa.PublicKey{Curve: tss.S256(), X: rootPoint.X(), Y: rootPoint.Y()}
	chainCode := make([]byte, 32)
	if _, err := rand.Read(chainCode); err != nil {
		return nil, derive.WalletMeta{}, fmt.Errorf("generate chain code: %w", err)
	}
	parties := make([]derive.Party, len(ids))
	for i, id := range ids {
		parties[i] = derive.Party{ID: id.Id, Key: new(big.Int).SetBytes(id.Key).String()}
	}
	meta := derive.WalletMeta{
		Version:   1,
		WalletID:  walletID,
		RootPub:   hex.EncodeToString(gethcrypto.CompressPubkey(pub)),
		ChainCode: hex.EncodeToString(chainCode),
		PartyIDs:  parties,
	}
	return keys, meta, nil
}

func generateSignerPreParams(ctx context.Context, count int) ([]*keygen.LocalPreParams, error) {
	ctx, cancel := context.WithTimeout(ctx, dkgTimeout)
	defer cancel()
	type result struct {
		index  int
		params *keygen.LocalPreParams
		err    error
	}
	results := make(chan result, count)
	for i := 0; i < count; i++ {
		go func(index int) {
			params, err := keygen.GeneratePreParamsWithContextAndRandom(ctx, rand.Reader)
			results <- result{index: index, params: params, err: err}
		}(i)
	}
	params := make([]*keygen.LocalPreParams, count)
	for range count {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err != nil {
				return nil, fmt.Errorf("generate signer-%d tss-lib pre-parameters: %w", result.index+1, result.err)
			}
			params[result.index] = result.params
		}
	}
	return params, nil
}

func buildLocalSaveData(ids tss.SortedPartyIDs, shares vss.Shares, commitments vss.Vs, preParams []*keygen.LocalPreParams) ([]keygen.LocalPartySaveData, error) {
	if len(ids) != 3 || len(shares) != len(ids) || len(preParams) != len(ids) || len(commitments) != 2 {
		return nil, errors.New("2-of-3 save data requires three parties, shares, and pre-parameter sets")
	}
	keys := make([]keygen.LocalPartySaveData, len(ids))
	for i, id := range ids {
		if shares[i] == nil || !shares[i].Verify(tss.S256(), 1, commitments) || preParams[i] == nil || !preParams[i].ValidateWithProof() {
			return nil, fmt.Errorf("invalid VSS share or tss-lib pre-parameters for party %s", id.Id)
		}
		save := keygen.NewLocalPartySaveData(len(ids))
		save.LocalPreParams = *preParams[i]
		save.Xi = new(big.Int).Set(shares[i].Share)
		save.ShareID = new(big.Int).Set(shares[i].ID)
		save.Ks = make([]*big.Int, len(ids))
		save.ECDSAPub = commitments[0]
		for j, party := range ids {
			shareID := new(big.Int).SetBytes(party.Key)
			save.Ks[j] = shareID
			save.NTildej[j] = preParams[j].NTildei
			save.H1j[j], save.H2j[j] = preParams[j].H1i, preParams[j].H2i
			save.PaillierPKs[j] = &preParams[j].PaillierSK.PublicKey
			point, err := evaluateVSSCommitment(commitments, shareID, tss.S256().Params().N)
			if err != nil {
				return nil, fmt.Errorf("evaluate public share for %s: %w", party.Id, err)
			}
			save.BigXj[j] = point
		}
		keys[i] = save
	}
	return keys, nil
}

func evaluateVSSCommitment(commitments vss.Vs, index, modulus *big.Int) (*tsscrypto.ECPoint, error) {
	if len(commitments) != 2 || commitments[0] == nil || commitments[1] == nil {
		return nil, errors.New("invalid degree-1 Feldman commitments")
	}
	power := new(big.Int).Mod(new(big.Int).Set(index), modulus)
	term := commitments[1].ScalarMult(power)
	if term == nil {
		return nil, errors.New("invalid public share commitment")
	}
	point, err := commitments[0].Add(term)
	if err != nil {
		return nil, err
	}
	return point, nil
}

func WriteWalletFiles(outputDir string, saves []keygen.LocalPartySaveData, meta derive.WalletMeta) error {
	if !walletIDPattern.MatchString(meta.WalletID) {
		return errors.New("invalid wallet ID")
	}
	if len(saves) != 3 {
		return errors.New("expected exactly three shares")
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(outputDir); err == nil {
		return fmt.Errorf("output directory already exists: %s", outputDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".wallet-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	for i, id := range meta.PartyIDs {
		if id.ID != fmt.Sprintf("node-%d", i+1) {
			return errors.New("unexpected node roster in wallet metadata")
		}
		dir := filepath.Join(tmp, id.ID, meta.WalletID)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		shareBytes, err := json.MarshalIndent(saves[i], "", "  ")
		if err != nil {
			return fmt.Errorf("encode save data for %s: %w", id.ID, err)
		}
		if err := writePrivateFile(filepath.Join(dir, "share.json"), shareBytes); err != nil {
			return err
		}
		if err := writePrivateFile(filepath.Join(dir, "wallet.json"), metaBytes); err != nil {
			return err
		}
	}
	publicDir := filepath.Join(tmp, "public", meta.WalletID)
	if err := os.MkdirAll(publicDir, 0755); err != nil {
		return err
	}
	if err := os.Chmod(publicDir, 0755); err != nil {
		return err
	}
	publicMetaPath := filepath.Join(publicDir, "wallet.json")
	if err := os.WriteFile(publicMetaPath, metaBytes, 0644); err != nil {
		return err
	}
	if err := os.Chmod(publicMetaPath, 0644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	if err := os.Rename(tmp, outputDir); err != nil {
		return fmt.Errorf("publish output directory: %w", err)
	}
	return nil
}

func writePrivateFile(path string, payload []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readPrivateKeyFile(path string) (*big.Int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return derive.ParsePrivateScalar(string(bytesTrimSpace(b)))
}

func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
