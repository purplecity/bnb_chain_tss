// Package tssadapter is the only application package that directly depends on
// BNB tss-lib. It owns the threshold mapping and creates fresh party objects
// for every DKG/signing attempt.
package tssadapter

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	CommitteeSize          = 3
	MinSigners             = 2
	bnbThreshold           = CommitteeSize - MinSigners
	defaultProtocolTimeout = 10 * time.Minute
)

type KeySet struct {
	Shares    []keygen.LocalPartySaveData
	PartyIDs  []string
	PartyKeys []*big.Int
	PublicKey *ecdsa.PublicKey
}

type Participant struct {
	ID        string
	UniqueKey []byte
}

func GenerateKeySet(ctx context.Context) (KeySet, error) {
	// The no-argument entry point is only for local demonstrations. Production
	// callers must provide stable peer identity keys via GenerateKeySetForCommittee.
	ids := tss.GenerateTestPartyIDs(CommitteeSize)
	participants := make([]Participant, len(ids))
	for i, id := range ids {
		participants[i] = Participant{ID: id.Id, UniqueKey: append([]byte(nil), id.Key...)}
	}
	return GenerateKeySetForCommittee(ctx, participants)
}

func GenerateKeySetForCommittee(ctx context.Context, members []Participant) (KeySet, error) {
	ids, err := sortedPartyIDs(members)
	if err != nil {
		return KeySet{}, err
	}
	ctxP2P := tss.NewPeerContext(ids)
	out := make(chan tss.Message, 4096)
	end := make(chan *keygen.LocalPartySaveData, CommitteeSize)
	parties := make([]tss.Party, CommitteeSize)
	for i, id := range ids {
		params := tss.NewParameters(tss.S256(), ctxP2P, id, CommitteeSize, bnbThreshold)
		params.SetConcurrency(1)
		parties[i] = keygen.NewLocalParty(params, out, end)
	}
	shares := make([]keygen.LocalPartySaveData, CommitteeSize)
	if err := runProtocol(ctx, parties, out, end, CommitteeSize, func(_ int, data *keygen.LocalPartySaveData) error {
		if data == nil || data.ECDSAPub == nil || !data.ECDSAPub.IsOnCurve() {
			return errors.New("DKG returned invalid save data")
		}
		i, err := data.OriginalIndex()
		if err != nil || i < 0 || i >= CommitteeSize {
			return errors.New("DKG share has invalid party index")
		}
		shares[i] = *data
		return nil
	}); err != nil {
		return KeySet{}, fmt.Errorf("2-of-3 DKG: %w", err)
	}
	pub := shares[0].ECDSAPub.ToECDSAPubKey()
	for i := range shares {
		if !shares[i].ECDSAPub.Equals(shares[0].ECDSAPub) {
			return KeySet{}, errors.New("DKG participants reported different public keys")
		}
	}
	partyNames := make([]string, len(ids))
	partyKeys := make([]*big.Int, len(ids))
	for i, id := range ids {
		partyNames[i] = id.Id
		partyKeys[i] = new(big.Int).Set(id.KeyInt())
	}
	return KeySet{Shares: shares, PartyIDs: partyNames, PartyKeys: partyKeys, PublicKey: pub}, nil
}

type Signature struct {
	R, S       *big.Int
	RecoveryID byte
	Raw        []byte
}

// SignPair signs a 32-byte chain-specific message digest using exactly two
// stored shares. The caller is responsible for deriving the digest only after
// decoding and validating the complete chain transaction.
func SignPair(ctx context.Context, keys KeySet, partyIndexes [2]int, digest []byte) (Signature, error) {
	if len(digest) != 32 {
		return Signature{}, errors.New("digest must be exactly 32 bytes")
	}
	if keys.PublicKey == nil || len(keys.Shares) != CommitteeSize || len(keys.PartyIDs) != CommitteeSize || len(keys.PartyKeys) != CommitteeSize {
		return Signature{}, errors.New("invalid key set")
	}
	if partyIndexes[0] < 0 || partyIndexes[0] >= CommitteeSize || partyIndexes[1] < 0 || partyIndexes[1] >= CommitteeSize || partyIndexes[0] == partyIndexes[1] {
		return Signature{}, errors.New("signing pair must contain two distinct committee members")
	}
	chosen := []int{partyIndexes[0], partyIndexes[1]}
	ids := make(tss.UnSortedPartyIDs, 0, MinSigners)
	for _, i := range chosen {
		if keys.PartyKeys[i] == nil || keys.PartyKeys[i].Sign() <= 0 {
			return Signature{}, errors.New("invalid party identity key")
		}
		ids = append(ids, tss.NewPartyID(keys.PartyIDs[i], keys.PartyIDs[i], new(big.Int).Set(keys.PartyKeys[i])))
	}
	sorted := tss.SortPartyIDs(ids)
	ctxP2P := tss.NewPeerContext(sorted)
	out := make(chan tss.Message, 4096)
	end := make(chan *common.SignatureData, MinSigners)
	parties := make([]tss.Party, MinSigners)
	for i, id := range sorted {
		originalIndex := -1
		for j, key := range keys.PartyKeys {
			if key.Cmp(id.KeyInt()) == 0 {
				originalIndex = j
				break
			}
		}
		if originalIndex < 0 {
			return Signature{}, errors.New("selected party identity is absent from committee")
		}
		params := tss.NewParameters(tss.S256(), ctxP2P, id, MinSigners, bnbThreshold)
		parties[i] = signing.NewLocalParty(new(big.Int).SetBytes(digest), params, keys.Shares[originalIndex], out, end)
	}
	var result *common.SignatureData
	if err := runProtocol(ctx, parties, out, end, MinSigners, func(_ int, sig *common.SignatureData) error {
		if sig == nil {
			return errors.New("signing returned empty signature")
		}
		if result == nil {
			result = sig
			return nil
		}
		if string(result.Signature) != string(sig.Signature) || string(result.SignatureRecovery) != string(sig.SignatureRecovery) {
			return errors.New("signers returned inconsistent signature data")
		}
		return nil
	}); err != nil {
		return Signature{}, fmt.Errorf("2-of-3 signing: %w", err)
	}
	if len(result.R) == 0 || len(result.S) == 0 || len(result.SignatureRecovery) == 0 {
		return Signature{}, errors.New("signature result is incomplete")
	}
	r, s := new(big.Int).SetBytes(result.R), new(big.Int).SetBytes(result.S)
	if !ecdsa.Verify(keys.PublicKey, digest, r, s) {
		return Signature{}, errors.New("signature did not verify against DKG public key")
	}
	recovery := result.SignatureRecovery[0]
	return Signature{R: r, S: s, RecoveryID: recovery, Raw: append([]byte(nil), result.Signature...)}, nil
}

func sortedPartyIDs(members []Participant) (tss.SortedPartyIDs, error) {
	return sortedPartyIDsForCount(members, CommitteeSize)
}

func sortedPartyIDsForCount(members []Participant, expected int) (tss.SortedPartyIDs, error) {
	if len(members) != expected {
		return nil, fmt.Errorf("party set must have exactly %d members", expected)
	}
	ids := make(tss.UnSortedPartyIDs, 0, len(members))
	seenIDs := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	for _, member := range members {
		if member.ID == "" || len(member.UniqueKey) == 0 {
			return nil, errors.New("committee member ID and unique identity key are required")
		}
		key := new(big.Int).SetBytes(member.UniqueKey)
		if key.Sign() <= 0 {
			return nil, errors.New("committee identity key must be positive")
		}
		if _, ok := seenIDs[member.ID]; ok {
			return nil, errors.New("committee member IDs must be unique")
		}
		seenIDs[member.ID] = struct{}{}
		fingerprint := key.String()
		if _, ok := seenKeys[fingerprint]; ok {
			return nil, errors.New("committee identity keys must be unique")
		}
		seenKeys[fingerprint] = struct{}{}
		ids = append(ids, tss.NewPartyID(member.ID, member.ID, key))
	}
	return tss.SortPartyIDs(ids), nil
}

func runProtocol[T any](parent context.Context, parties []tss.Party, out <-chan tss.Message, end <-chan T, expected int, accept func(int, T) error) error {
	ctx, cancel := context.WithTimeout(parent, defaultProtocolTimeout)
	defer cancel()
	errCh := make(chan error, len(parties))
	index := make(map[string]int, len(parties))
	for i, party := range parties {
		index[party.PartyID().Id] = i
	}
	for _, party := range parties {
		p := party
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}
	completed := 0
	for completed < expected {
		select {
		case <-ctx.Done():
			return fmt.Errorf("protocol timed out or canceled: %w", ctx.Err())
		case err := <-errCh:
			return fmt.Errorf("party start failed: %w", err)
		case value := <-end:
			idx := completed
			if err := accept(idx, value); err != nil {
				return err
			}
			completed++
		case msg := <-out:
			from := msg.GetFrom()
			if from == nil {
				return errors.New("protocol message has no sender")
			}
			if msg.GetTo() == nil {
				for _, receiver := range parties {
					if receiver.PartyID().Id == from.Id {
						continue
					}
					if err := deliver(receiver, msg); err != nil {
						return err
					}
				}
			} else {
				for _, to := range msg.GetTo() {
					receiverIndex, ok := index[to.Id]
					if !ok {
						return fmt.Errorf("protocol message targets nonparticipant %q", to.Id)
					}
					receiver := parties[receiverIndex]
					if receiver.PartyID().Id == from.Id {
						return errors.New("protocol attempted to send a message to itself")
					}
					if err := deliver(receiver, msg); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func deliver(receiver tss.Party, msg tss.Message) error {
	wire, _, err := msg.WireBytes()
	if err != nil {
		return fmt.Errorf("encode tss message: %w", err)
	}
	parsed, err := tss.ParseWireMessage(wire, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		return fmt.Errorf("decode tss message: %w", err)
	}
	if _, err := receiver.Update(parsed); err != nil {
		return fmt.Errorf("update tss party: %w", err)
	}
	return nil
}
