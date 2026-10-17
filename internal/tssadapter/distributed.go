package tssadapter

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/purplecity/bnb_chain_tss/internal/transport"
)

type SessionMeta struct {
	SessionID string
	AttemptID string
	KeyID     string
	Epoch     uint64
}

type ProtocolSession struct {
	runtime *partyRuntime
	result  <-chan any
	stop    chan struct{}
	started atomic.Bool
}

type partyRuntime struct {
	party      tss.Party
	out        chan tss.Message
	end        <-chan any
	transport  *transport.Session
	ids        map[string]*tss.PartyID
	mu         sync.Mutex
	ready      bool
	pending    []inboundMessage
	signDigest []byte
	signPub    *ecdsa.PublicKey
}

type inboundMessage struct {
	sender    string
	payload   []byte
	broadcast bool
}

func NewDistributedDKG(meta SessionMeta, localID string, members []Participant, mesh transport.Mesh) (*ProtocolSession, error) {
	ids, err := sortedPartyIDs(members)
	if err != nil {
		return nil, err
	}
	local, ok := findParty(ids, localID)
	if !ok {
		return nil, errors.New("local party is outside DKG committee")
	}
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(ids), local, len(ids), bnbThreshold)
	params.SetConcurrency(1)
	params.SetSafePrimeGenTimeout(defaultProtocolTimeout)
	out := make(chan tss.Message, 4096)
	end := make(chan *keygen.LocalPartySaveData, 1)
	party := keygen.NewLocalParty(params, out, end)
	stop := make(chan struct{})
	bridge := bridgeResult(end, stop)
	runtime, err := newPartyRuntime(meta, localID, ids, mesh, party, out, bridge)
	if err != nil {
		return nil, err
	}
	return &ProtocolSession{runtime: runtime, result: bridge, stop: stop}, nil
}

func NewDistributedSign(meta SessionMeta, localID string, members, selected []Participant, share keygen.LocalPartySaveData, digest []byte, mesh transport.Mesh) (*ProtocolSession, error) {
	if len(digest) != 32 {
		return nil, errors.New("digest must be exactly 32 bytes")
	}
	fullIDs, err := sortedPartyIDs(members)
	if err != nil {
		return nil, err
	}
	if err := validateLocalShare(fullIDs, localID, share); err != nil {
		return nil, err
	}
	ids, err := sortedPartyIDsForCount(selected, MinSigners)
	if err != nil {
		return nil, err
	}
	if len(ids) != MinSigners {
		return nil, errors.New("signing session must contain exactly two parties")
	}
	local, ok := findParty(ids, localID)
	if !ok {
		return nil, errors.New("local party is not selected for signing")
	}
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(ids), local, len(ids), bnbThreshold)
	out := make(chan tss.Message, 4096)
	end := make(chan *common.SignatureData, 1)
	party := signing.NewLocalParty(new(big.Int).SetBytes(digest), params, share, out, end)
	stop := make(chan struct{})
	bridge := bridgeResult(end, stop)
	runtime, err := newPartyRuntime(meta, localID, ids, mesh, party, out, bridge)
	if err != nil {
		return nil, err
	}
	runtime.signDigest = append([]byte(nil), digest...)
	runtime.signPub = share.ECDSAPub.ToECDSAPubKey()
	return &ProtocolSession{runtime: runtime, result: bridge, stop: stop}, nil
}

func newPartyRuntime(meta SessionMeta, localID string, ids tss.SortedPartyIDs, mesh transport.Mesh, party tss.Party, out chan tss.Message, end <-chan any) (*partyRuntime, error) {
	if meta.SessionID == "" || meta.AttemptID == "" || meta.KeyID == "" || meta.Epoch == 0 {
		return nil, errors.New("session, attempt, key and epoch are required")
	}
	runtime := &partyRuntime{party: party, out: out, end: end, ids: map[string]*tss.PartyID{}}
	members := make([]string, len(ids))
	for i, id := range ids {
		members[i] = id.Id
		runtime.ids[id.Id] = id
	}
	network, err := transport.NewSession(transport.SessionConfig{SessionID: meta.SessionID, AttemptID: meta.AttemptID, KeyID: meta.KeyID, Epoch: meta.Epoch, LocalParty: localID, Members: members}, mesh, runtime.receive)
	if err != nil {
		return nil, err
	}
	runtime.transport = network
	return runtime, nil
}

func (p *ProtocolSession) TransportSession() *transport.Session { return p.runtime.transport }

func (p *ProtocolSession) Run(ctx context.Context) (any, error) {
	if !p.started.CompareAndSwap(false, true) {
		return nil, errors.New("protocol session can only run once")
	}
	defer close(p.stop)
	ctx, cancel := context.WithTimeout(ctx, defaultProtocolTimeout)
	defer cancel()
	if err := p.runtime.party.Start(); err != nil {
		return nil, fmt.Errorf("start TSS party: %w", err)
	}
	if err := p.runtime.activate(ctx); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("TSS session canceled or timed out: %w", ctx.Err())
		case <-p.runtime.transport.Done():
			return nil, fmt.Errorf("TSS transport aborted: %w", p.runtime.transport.Aborted())
		case message := <-p.runtime.out:
			if err := p.runtime.send(ctx, message); err != nil {
				return nil, p.runtime.transport.Abort(err)
			}
		case result := <-p.result:
			if err := p.runtime.verifyResult(result); err != nil {
				return nil, err
			}
			return result, nil
		}
	}
}

func (p *partyRuntime) receive(ctx context.Context, sender string, payload []byte, broadcast bool) error {
	p.mu.Lock()
	if !p.ready {
		if len(p.pending) >= 256 {
			p.mu.Unlock()
			return p.transport.Abort(errors.New("too many protocol messages before party startup"))
		}
		p.pending = append(p.pending, inboundMessage{sender: sender, payload: append([]byte(nil), payload...), broadcast: broadcast})
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	return p.update(ctx, sender, payload, broadcast)
}

func (p *partyRuntime) activate(ctx context.Context) error {
	p.mu.Lock()
	p.ready = true
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, message := range pending {
		if err := p.update(ctx, message.sender, message.payload, message.broadcast); err != nil {
			return err
		}
	}
	return nil
}

func (p *partyRuntime) update(_ context.Context, sender string, payload []byte, broadcast bool) error {
	from, ok := p.ids[sender]
	if !ok {
		return p.transport.Abort(errors.New("message sender is outside TSS party context"))
	}
	if _, err := p.party.UpdateFromBytes(payload, from, broadcast); err != nil {
		return p.transport.Abort(fmt.Errorf("update TSS party: %w", err))
	}
	return nil
}

func (p *partyRuntime) send(ctx context.Context, message tss.Message) error {
	wire, _, err := message.WireBytes()
	if err != nil {
		return fmt.Errorf("encode TSS message: %w", err)
	}
	if message.GetTo() == nil {
		return p.transport.Broadcast(ctx, wire)
	}
	for _, recipient := range message.GetTo() {
		if recipient == nil {
			return errors.New("TSS message has nil recipient")
		}
		if err := p.transport.SendDirect(ctx, recipient.Id, wire); err != nil {
			return err
		}
	}
	return nil
}

func (p *partyRuntime) verifyResult(result any) error {
	switch value := result.(type) {
	case *keygen.LocalPartySaveData:
		if value == nil || value.ECDSAPub == nil || !value.ECDSAPub.IsOnCurve() {
			return errors.New("distributed DKG returned invalid save data")
		}
		return nil
	case *common.SignatureData:
		if value == nil || len(value.R) == 0 || len(value.S) == 0 || len(value.SignatureRecovery) == 0 {
			return errors.New("distributed signing returned incomplete signature")
		}
		if p.signPub == nil || len(p.signDigest) != 32 || !ecdsa.Verify(p.signPub, p.signDigest, new(big.Int).SetBytes(value.R), new(big.Int).SetBytes(value.S)) {
			return errors.New("distributed signature does not verify against the local share public key and digest")
		}
		return nil
	default:
		return fmt.Errorf("unexpected TSS result type %T", result)
	}
}

func bridgeResult[T any](end <-chan T, stop <-chan struct{}) <-chan any {
	result := make(chan any, 1)
	go func() {
		select {
		case value := <-end:
			result <- value
		case <-stop:
			return
		}
	}()
	return result
}

func findParty(ids tss.SortedPartyIDs, id string) (*tss.PartyID, bool) {
	for _, party := range ids {
		if party.Id == id {
			return party, true
		}
	}
	return nil, false
}

func validateLocalShare(ids tss.SortedPartyIDs, localID string, share keygen.LocalPartySaveData) error {
	if share.ShareID == nil || share.Xi == nil {
		return errors.New("local share data is incomplete")
	}
	index, err := share.OriginalIndex()
	if err != nil || index < 0 || index >= len(ids) {
		return errors.New("local share does not match configured committee")
	}
	if ids[index].KeyInt().Cmp(share.ShareID) != 0 || ids[index].Id != localID {
		return errors.New("local share belongs to a different logical party")
	}
	return nil
}
