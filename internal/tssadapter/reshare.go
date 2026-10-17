package tssadapter

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// ReshareKeySet changes the 2-of-3 committee while preserving the ECDSA
// public key. Exactly two old members must authorize a transition; every new
// member receives a new share. This is for controlled migration and is not a
// remedy for a compromised signing quorum: after suspected key compromise,
// generate a fresh key and move funds to its new address.
func ReshareKeySet(ctx context.Context, old KeySet, oldIndexes [2]int, newMembers []Participant) (KeySet, error) {
	if old.PublicKey == nil || len(old.Shares) != CommitteeSize || len(old.PartyIDs) != CommitteeSize || len(old.PartyKeys) != CommitteeSize {
		return KeySet{}, errors.New("invalid old key set")
	}
	if oldIndexes[0] == oldIndexes[1] || oldIndexes[0] < 0 || oldIndexes[1] < 0 || oldIndexes[0] >= CommitteeSize || oldIndexes[1] >= CommitteeSize {
		return KeySet{}, errors.New("resharing requires two distinct old signers")
	}
	newIDs, err := sortedPartyIDs(newMembers)
	if err != nil {
		return KeySet{}, err
	}
	oldMembers := make([]Participant, CommitteeSize)
	for i := range oldMembers {
		oldMembers[i] = Participant{ID: old.PartyIDs[i], UniqueKey: old.PartyKeys[i].Bytes()}
	}
	allOldIDs, err := sortedPartyIDs(oldMembers)
	if err != nil {
		return KeySet{}, err
	}
	oldSubsetUnsorted := tss.UnSortedPartyIDs{allOldIDs[oldIndexes[0]], allOldIDs[oldIndexes[1]]}
	oldIDs := tss.SortPartyIDs(oldSubsetUnsorted)
	oldIdentitySet := map[string]struct{}{}
	for _, id := range oldIDs {
		oldIdentitySet[id.Id] = struct{}{}
	}
	for _, id := range newIDs {
		if _, overlaps := oldIdentitySet[id.Id]; overlaps {
			return KeySet{}, errors.New("in-process resharing helper requires disjoint old and new party identities")
		}
	}
	oldCtx, newCtx := tss.NewPeerContext(oldIDs), tss.NewPeerContext(newIDs)
	out := make(chan tss.Message, 8192)
	end := make(chan *keygen.LocalPartySaveData, len(oldIDs)+len(newIDs))
	parties := make(map[string]tss.Party, len(oldIDs)+len(newIDs))
	oldSet := map[string]keygen.LocalPartySaveData{}
	for _, id := range oldIDs {
		idx := -1
		for i := range old.PartyIDs {
			if old.PartyIDs[i] == id.Id {
				idx = i
				break
			}
		}
		if idx < 0 {
			return KeySet{}, errors.New("old signer share is missing")
		}
		oldSet[id.Id] = old.Shares[idx]
	}
	for _, id := range oldIDs {
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx, id, len(oldIDs), bnbThreshold, len(newIDs), bnbThreshold)
		params.SetConcurrency(1)
		parties[id.Id] = resharing.NewLocalParty(params, oldSet[id.Id], out, end)
	}
	for _, id := range newIDs {
		params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx, id, len(oldIDs), bnbThreshold, len(newIDs), bnbThreshold)
		params.SetConcurrency(1)
		parties[id.Id] = resharing.NewLocalParty(params, keygen.NewLocalPartySaveData(len(newIDs)), out, end)
	}
	errCh := make(chan error, len(parties))
	for _, party := range parties {
		p := party
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}
	newShares := make([]keygen.LocalPartySaveData, len(newIDs))
	ended := 0
	for ended < len(parties) {
		select {
		case <-ctx.Done():
			return KeySet{}, fmt.Errorf("resharing canceled or timed out: %w", ctx.Err())
		case err := <-errCh:
			return KeySet{}, fmt.Errorf("resharing protocol: %w", err)
		case result := <-end:
			ended++
			if result != nil && result.Xi != nil {
				i, e := result.OriginalIndex()
				if e != nil || i < 0 || i >= len(newShares) {
					return KeySet{}, errors.New("resharing returned invalid new share index")
				}
				newShares[i] = *result
			}
		case message := <-out:
			dest := message.GetTo()
			if dest == nil {
				return KeySet{}, errors.New("resharing message is missing destinations")
			}
			deliverTo := func(targetIDs tss.SortedPartyIDs, destinations []*tss.PartyID) error {
				for _, to := range destinations {
					if int(to.Index) >= len(targetIDs) {
						return errors.New("resharing destination outside committee")
					}
					target := parties[targetIDs[to.Index].Id]
					if target == nil {
						return errors.New("resharing destination party missing")
					}
					if err := deliver(target, message); err != nil {
						return err
					}
				}
				return nil
			}
			if message.IsToOldCommittee() || message.IsToOldAndNewCommittees() {
				oldDest := dest
				if message.IsToOldAndNewCommittees() && len(oldDest) > len(oldIDs) {
					oldDest = oldDest[:len(oldIDs)]
				}
				if err := deliverTo(oldIDs, oldDest); err != nil {
					return KeySet{}, err
				}
			}
			if !message.IsToOldCommittee() || message.IsToOldAndNewCommittees() {
				if err := deliverTo(newIDs, dest); err != nil {
					return KeySet{}, err
				}
			}
		}
	}
	for i := range newShares {
		if newShares[i].Xi == nil || newShares[i].ECDSAPub == nil || !newShares[i].ECDSAPub.Equals(old.Shares[0].ECDSAPub) {
			return KeySet{}, errors.New("new shares do not preserve the old public key")
		}
	}
	partyNames := make([]string, len(newIDs))
	partyKeys := make([]*big.Int, len(newIDs))
	for i, id := range newIDs {
		partyNames[i] = id.Id
		partyKeys[i] = new(big.Int).Set(id.KeyInt())
	}
	result := KeySet{Shares: newShares, PartyIDs: partyNames, PartyKeys: partyKeys, PublicKey: old.PublicKey}
	// Prove the new committee is immediately usable, rather than accepting a
	// resharing result that only appears structurally valid.
	digest := make([]byte, 32)
	digest[31] = 1
	if _, err := SignPair(ctx, result, [2]int{0, 1}, digest); err != nil {
		return KeySet{}, fmt.Errorf("new committee signing self-check: %w", err)
	}
	return result, nil
}
