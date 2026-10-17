package tssadapter

import (
	"context"
	"testing"
	"time"
)

func TestReshareChangesCommitteeKeepsPublicKeyAndCanSign(t *testing.T) {
	if testing.Short() {
		t.Skip("cryptographic protocol integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	old, err := GenerateKeySet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newMembers := []Participant{{ID: "replacement-a", UniqueKey: []byte{21}}, {ID: "replacement-b", UniqueKey: []byte{22}}, {ID: "replacement-c", UniqueKey: []byte{23}}}
	reshared, err := ReshareKeySet(ctx, old, [2]int{0, 1}, newMembers)
	if err != nil {
		t.Fatal(err)
	}
	if !reshared.PublicKey.Equal(old.PublicKey) {
		t.Fatal("resharing changed the public key")
	}
	digest := make([]byte, 32)
	digest[0] = 9
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		if _, err := SignPair(ctx, reshared, pair, digest); err != nil {
			t.Fatalf("new pair %v failed signing: %v", pair, err)
		}
	}
	for _, id := range reshared.PartyIDs {
		if id == old.PartyIDs[0] || id == old.PartyIDs[1] || id == old.PartyIDs[2] {
			t.Fatalf("new committee unexpectedly reused old identity %s", id)
		}
	}
}
