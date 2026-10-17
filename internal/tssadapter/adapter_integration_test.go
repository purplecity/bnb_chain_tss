package tssadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/purplecity/bnb_chain_tss/internal/sharestore"
)

func TestDKGAndAllTwoOfThreeSigningPairs(t *testing.T) {
	if testing.Short() {
		t.Skip("real BNB DKG integration is excluded by -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	keys, err := GenerateKeySet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Shares) != 3 || keys.PublicKey == nil || !keys.PublicKey.Curve.IsOnCurve(keys.PublicKey.X, keys.PublicKey.Y) {
		t.Fatal("DKG returned an invalid committee key")
	}
	// Confirm that the exact complete SaveData objects can be serialized and
	// decoded before relying on them as the persistence boundary.
	for i, share := range keys.Shares {
		if share.Xi == nil || share.ShareID == nil || len(share.Ks) != CommitteeSize || len(share.PaillierPKs) != CommitteeSize {
			t.Fatalf("share %d is incomplete", i)
		}
		dataKey := randBytes(32)
		identity := sharestore.Identity{KeyID: "integration-key", Epoch: 1, Party: keys.PartyIDs[i], Schema: sharestore.SchemaVersion}
		envelope, err := sharestore.Encrypt(share, identity, dataKey)
		if err != nil {
			t.Fatalf("encrypt complete share %d: %v", i, err)
		}
		restored, err := sharestore.Decrypt(envelope, identity, dataKey)
		if err != nil {
			t.Fatalf("restore complete share %d: %v", i, err)
		}
		if restored.Xi.Cmp(share.Xi) != 0 || restored.ShareID.Cmp(share.ShareID) != 0 || !restored.ECDSAPub.Equals(share.ECDSAPub) {
			t.Fatalf("share %d changed across encrypted persistence round trip", i)
		}
		keys.Shares[i] = restored
	}

	digest := sha256.Sum256([]byte("bn tss wallet integration test intent"))
	pairs := [][2]int{{0, 1}, {0, 2}, {1, 2}}
	for _, pair := range pairs {
		pair := pair
		t.Run(keys.PartyIDs[pair[0]]+"_"+keys.PartyIDs[pair[1]], func(t *testing.T) {
			sig, err := SignPair(ctx, keys, pair, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.Verify(keys.PublicKey, digest[:], sig.R, sig.S) {
				t.Fatal("signature failed ECDSA verification")
			}
			if len(sig.Raw) != 64 || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
				t.Fatal("signature encoding is incomplete")
			}
			wrongDigest := sha256.Sum256([]byte("different transaction"))
			if ecdsa.Verify(keys.PublicKey, wrongDigest[:], sig.R, sig.S) {
				t.Fatal("signature verified for a different digest")
			}
		})
	}
	if _, err := SignPair(ctx, keys, [2]int{0, 0}, digest[:]); err == nil {
		t.Fatal("duplicate party pair should be rejected")
	}
	if _, err := SignPair(ctx, keys, [2]int{0, 1}, digest[:31]); err == nil {
		t.Fatal("non-32-byte digest should be rejected")
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func TestThresholdMappingAndPartyIDs(t *testing.T) {
	if CommitteeSize != 3 || MinSigners != 2 || bnbThreshold != 1 {
		t.Fatal("business 2-of-3 threshold must map to BNB threshold=1")
	}
	members := []Participant{{ID: "a", UniqueKey: []byte{1}}, {ID: "b", UniqueKey: []byte{2}}, {ID: "c", UniqueKey: []byte{3}}}
	ids, err := sortedPartyIDs(members)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, id := range ids {
		if id.Index != i || seen[id.Id] {
			t.Fatalf("party IDs are not unique and ordered at %d", i)
		}
		seen[id.Id] = true
	}
	if len(seen) != CommitteeSize {
		t.Fatal("wrong party count")
	}
	if _, err := sortedPartyIDs([]Participant{members[0], members[0], members[2]}); err == nil {
		t.Fatal("duplicate committee identity accepted")
	}
}
