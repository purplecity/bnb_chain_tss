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
	"testing"
	"time"

	tsscommon "github.com/bnb-chain/tss-lib/v4/common"
	tsscrypto "github.com/bnb-chain/tss-lib/v4/crypto"
	"github.com/bnb-chain/tss-lib/v4/crypto/vss"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v4/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v4/tss"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
)

func TestReadPrivateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private_key.txt")
	if err := os.WriteFile(path, []byte("  0000000000000000000000000000000000000000000000000000000000000001\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := readPrivateKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if key.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("unexpected key %s", key)
	}
	if err := os.WriteFile(path, []byte("0x0000000000000000000000000000000000000000000000000000000000000001"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKeyFile(path); err == nil {
		t.Fatal("0x-prefixed key accepted")
	}
}

func TestGenerateSharesAndSignDerivedAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real v4 DKG and threshold signing protocol")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	secret := big.NewInt(1)
	saves, meta, err := GenerateWalletShares(ctx, "integration-wallet", secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(saves) != 3 {
		t.Fatalf("got %d shares", len(saves))
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		pairShares := vss.Shares{
			&vss.Share{Threshold: 1, ID: saves[pair[0]].ShareID, Share: saves[pair[0]].Xi},
			&vss.Share{Threshold: 1, ID: saves[pair[1]].ShareID, Share: saves[pair[1]].Xi},
		}
		got, err := pairShares.ReConstruct(tss.S256())
		if err != nil {
			t.Fatal(err)
		}
		if got.Cmp(secret) != 0 {
			t.Fatalf("shares %v reconstruct %s", pair, got)
		}
	}
	for i := range saves {
		encoded, err := json.Marshal(saves[i])
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip keygen.LocalPartySaveData
		if err := json.Unmarshal(encoded, &roundTrip); err != nil {
			t.Fatalf("JSON round trip for signer %d: %v", i, err)
		}
		roundTrip.ECDSAPub.SetCurve(tss.S256())
		if roundTrip.ECDSAPub.X().Cmp(saves[i].ECDSAPub.X()) != 0 {
			t.Fatal("JSON round trip changed public key")
		}
	}
	out := filepath.Join(t.TempDir(), "wallet-output")
	if err := WriteWalletFiles(out, saves, meta); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		sharePath := filepath.Join(out, fmt.Sprintf("node-%d", i), meta.WalletID, "share.json")
		info, err := os.Stat(sharePath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("share file mode is %o, want 0600", info.Mode().Perm())
		}
	}
	publicMeta := filepath.Join(out, "public", meta.WalletID, "wallet.json")
	publicInfo, err := os.Stat(publicMeta)
	if err != nil {
		t.Fatal(err)
	}
	if publicInfo.Mode().Perm() != 0644 {
		t.Fatalf("public metadata mode is %o, want 0644", publicInfo.Mode().Perm())
	}
	if err := WriteWalletFiles(out, saves, meta); err == nil {
		t.Fatal("existing output directory was overwritten")
	}

	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	derived, tweak, err := derive.Derive(meta, 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	childBytes, err := hex.DecodeString(derived.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	childPub, err := gethcrypto.UnmarshalPubkey(childBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := signDerivedInProcess(ctx, saves, meta, tweak, childPub, digest); err != nil {
		t.Fatal(err)
	}
}

func signDerivedInProcess(ctx context.Context, saves []keygen.LocalPartySaveData, meta derive.WalletMeta, tweak *big.Int, childPub *ecdsa.PublicKey, digest []byte) error {
	ids := make(tss.UnSortedPartyIDs, len(meta.PartyIDs))
	for i, p := range meta.PartyIDs {
		key, _ := new(big.Int).SetString(p.Key, 10)
		ids[i] = tss.NewPartyID(p.ID, p.ID, key)
	}
	sorted := tss.SortPartyIDs(ids)
	prepared := make([]keygen.LocalPartySaveData, len(saves))
	for i := range saves {
		prepared[i] = saves[i]
		prepared[i].BigXj = append([]*tsscrypto.ECPoint(nil), saves[i].BigXj...)
	}
	if err := signing.UpdatePublicKeyAndAdjustBigXj(tweak, prepared, childPub, tss.S256()); err != nil {
		return err
	}
	params := make([]*tss.Parameters, len(sorted))
	nonce := big.NewInt(99)
	for i, id := range sorted {
		localIDs := make(tss.UnSortedPartyIDs, len(meta.PartyIDs))
		for j, party := range meta.PartyIDs {
			key, _ := new(big.Int).SetString(party.Key, 10)
			localIDs[j] = tss.NewPartyID(party.ID, party.ID, key)
		}
		localRoster := tss.SortPartyIDs(localIDs)
		localID := localRoster[i]
		if localID.Id != id.Id {
			return fmt.Errorf("local roster ordering changed for party %s", id.Id)
		}
		params[i] = tss.NewParameters(tss.S256(), tss.NewPeerContext(localRoster), localID, 3, 1)
		params[i].SetSessionNonce(new(big.Int).Set(nonce))
	}
	out := make(chan tss.Message, 512)
	end := make(chan *tsscommon.SignatureData, 3)
	errCh := make(chan error, 6)
	parties := make([]tss.Party, 3)
	for i := range parties {
		parties[i] = signing.NewLocalPartyWithKDD(new(big.Int).SetBytes(digest), params[i], prepared[i], new(big.Int).Set(tweak), out, end)
		p := parties[i]
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}
	count := 0
	for count < 3 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case sig := <-end:
			if sig == nil {
				return errors.New("empty tss signature")
			}
			if !ecdsa.Verify(childPub, digest, new(big.Int).SetBytes(sig.R), new(big.Int).SetBytes(sig.S)) {
				return errors.New("derived signature verification failed")
			}
			count++
		case msg := <-out:
			wire, routing, err := msg.WireBytes()
			if err != nil {
				return err
			}
			targets := msg.GetTo()
			if targets == nil {
				for _, id := range sorted {
					if id.Index != msg.GetFrom().Index {
						ok, err := parties[id.Index].UpdateFromBytes(wire, msg.GetFrom(), routing.IsBroadcast)
						if err != nil {
							return err
						}
						if !ok {
							return errors.New("party rejected broadcast")
						}
					}
				}
				continue
			}
			for _, id := range targets {
				ok, err := parties[id.Index].UpdateFromBytes(wire, msg.GetFrom(), routing.IsBroadcast)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("party rejected direct message")
				}
			}
		}
	}
	return nil
}
