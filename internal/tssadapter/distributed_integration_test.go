package tssadapter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/purplecity/bnb_chain_tss/internal/transport"
)

type inMemoryMesh struct {
	local string
	peers map[string]*transport.Session
	mu    *sync.RWMutex
}

func (m *inMemoryMesh) Send(ctx context.Context, to string, frame transport.Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.RLock()
	peer := m.peers[to]
	m.mu.RUnlock()
	if peer == nil {
		return fmt.Errorf("peer %s is not registered", to)
	}
	return peer.Receive(ctx, m.local, frame)
}

func TestDistributedPartiesRunDKGAndAllSigningPairs(t *testing.T) {
	if testing.Short() {
		t.Skip("distributed real DKG integration is excluded by -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	members := []Participant{{ID: "signer-a", UniqueKey: []byte{11}}, {ID: "signer-b", UniqueKey: []byte{22}}, {ID: "signer-c", UniqueKey: []byte{33}}}
	meshMu := &sync.RWMutex{}
	peerSessions := map[string]*transport.Session{}
	meshes := map[string]*inMemoryMesh{}
	for _, member := range members {
		meshes[member.ID] = &inMemoryMesh{local: member.ID, peers: peerSessions, mu: meshMu}
	}
	dkgSessions := map[string]*ProtocolSession{}
	meta := SessionMeta{SessionID: "dkg-session", AttemptID: "dkg-attempt-1", KeyID: "integration-key", Epoch: 1}
	for _, member := range members {
		session, err := NewDistributedDKG(meta, member.ID, members, meshes[member.ID])
		if err != nil {
			t.Fatal(err)
		}
		dkgSessions[member.ID] = session
		peerSessions[member.ID] = session.TransportSession()
	}
	results := runSessions(ctx, t, dkgSessions)
	shares := make([]keygen.LocalPartySaveData, 3)
	for index, member := range mustSortedMembers(t, members) {
		shares[index] = *(results[member.ID].(*keygen.LocalPartySaveData))
	}
	for i := 1; i < len(shares); i++ {
		if !shares[0].ECDSAPub.Equals(shares[i].ECDSAPub) {
			t.Fatal("distributed DKG parties disagree on public key")
		}
	}
	for pairIndex, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		selected := []Participant{members[pair[0]], members[pair[1]]}
		// Keep order-independent identities and use a distinct session attempt
		// for each signing pair.
		pairMeta := SessionMeta{SessionID: fmt.Sprintf("sign-session-%d", pairIndex), AttemptID: fmt.Sprintf("sign-attempt-%d", pairIndex), KeyID: "integration-key", Epoch: 1}
		pairSessions := map[string]*ProtocolSession{}
		for _, member := range selected {
			originalIndex := -1
			for i, candidate := range members {
				if candidate.ID == member.ID {
					originalIndex = i
					break
				}
			}
			if originalIndex < 0 {
				t.Fatal("test committee member missing")
			}
			session, err := NewDistributedSign(pairMeta, member.ID, members, selected, shares[originalIndex], []byte("0123456789abcdef0123456789abcdef"), meshes[member.ID])
			if err != nil {
				t.Fatal(err)
			}
			pairSessions[member.ID] = session
			peerSessions[member.ID] = session.TransportSession()
		}
		pairResults := runSessions(ctx, t, pairSessions)
		a := pairResults[selected[0].ID].(*common.SignatureData)
		b := pairResults[selected[1].ID].(*common.SignatureData)
		if !bytes.Equal(a.Signature, b.Signature) {
			t.Fatalf("signers %s and %s returned different signatures", selected[0].ID, selected[1].ID)
		}
		if !ecdsa.Verify(shares[0].ECDSAPub.ToECDSAPubKey(), []byte("0123456789abcdef0123456789abcdef"), new(big.Int).SetBytes(a.R), new(big.Int).SetBytes(a.S)) {
			t.Fatalf("signers %s and %s produced an invalid ECDSA signature", selected[0].ID, selected[1].ID)
		}
	}
}

func runSessions(ctx context.Context, t *testing.T, sessions map[string]*ProtocolSession) map[string]any {
	t.Helper()
	results := make(chan struct {
		id     string
		result any
		err    error
	}, len(sessions))
	for id, session := range sessions {
		id, session := id, session
		go func() {
			result, err := session.Run(ctx)
			results <- struct {
				id     string
				result any
				err    error
			}{id, result, err}
		}()
	}
	completed := make(map[string]any, len(sessions))
	for range sessions {
		select {
		case <-ctx.Done():
			t.Fatalf("distributed protocol timed out: %v", ctx.Err())
		case item := <-results:
			if item.err != nil {
				t.Fatalf("party %s failed: %v", item.id, item.err)
			}
			completed[item.id] = item.result
		}
	}
	return completed
}

func mustSortedMembers(t *testing.T, members []Participant) []Participant {
	t.Helper()
	ids, err := sortedPartyIDs(members)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]Participant, len(ids))
	for i, id := range ids {
		out[i] = Participant{ID: id.Id, UniqueKey: append([]byte(nil), id.Key...)}
	}
	return out
}
