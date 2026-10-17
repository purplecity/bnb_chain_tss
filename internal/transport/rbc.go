// Package transport implements session-bound peer delivery with a fail-closed
// all-member echo barrier for BNB tss-lib broadcast messages. Mesh.Send must be
// mutually authenticated and map the transport peer identity to Frame.Sender.
package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

type Kind string

const (
	KindBroadcast Kind = "broadcast"
	KindEcho      Kind = "echo"
	KindDirect    Kind = "direct"
)

type Frame struct {
	SessionID string `json:"session_id"`
	AttemptID string `json:"attempt_id"`
	KeyID     string `json:"key_id"`
	Epoch     uint64 `json:"epoch"`
	Kind      Kind   `json:"kind"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Origin    string `json:"origin,omitempty"`
	Sequence  uint64 `json:"sequence"`
	Payload   []byte `json:"payload,omitempty"`
	Digest    []byte `json:"digest,omitempty"`
}

type Mesh interface {
	Send(ctx context.Context, recipient string, frame Frame) error
}
type Deliver func(ctx context.Context, sender string, payload []byte, broadcast bool) error

type SessionConfig struct {
	SessionID       string
	AttemptID       string
	KeyID           string
	Epoch           uint64
	LocalParty      string
	Members         []string
	MaxMessageBytes int
	MaxSequence     uint64
}

type messageKey struct {
	Origin   string
	Sequence uint64
}
type candidate struct {
	payload []byte
	digest  [32]byte
}

type Session struct {
	mu                sync.Mutex
	outboundMu        sync.Mutex
	config            SessionConfig
	members           map[string]struct{}
	mesh              Mesh
	deliver           Deliver
	broadcastSequence uint64
	directSequence    uint64
	candidates        map[messageKey]candidate
	echoes            map[messageKey]map[string][32]byte
	delivered         map[messageKey]struct{}
	directSeen        map[string]map[uint64][32]byte
	aborted           error
	abortCh           chan struct{}
}

func NewSession(config SessionConfig, mesh Mesh, deliver Deliver) (*Session, error) {
	if config.SessionID == "" || config.AttemptID == "" || config.KeyID == "" || config.Epoch == 0 || config.LocalParty == "" || mesh == nil || deliver == nil {
		return nil, errors.New("incomplete protocol session configuration")
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = 1 << 20
	}
	if config.MaxSequence == 0 {
		config.MaxSequence = 4096
	}
	members := make(map[string]struct{}, len(config.Members))
	for _, member := range config.Members {
		if member == "" {
			return nil, errors.New("empty committee member")
		}
		if _, ok := members[member]; ok {
			return nil, errors.New("duplicate committee member")
		}
		members[member] = struct{}{}
	}
	if len(members) < 2 || len(members) > 3 {
		return nil, errors.New("2-of-3 transport requires two or three committee members")
	}
	if _, ok := members[config.LocalParty]; !ok {
		return nil, errors.New("local party is not a committee member")
	}
	return &Session{config: config, members: members, mesh: mesh, deliver: deliver, candidates: map[messageKey]candidate{}, echoes: map[messageKey]map[string][32]byte{}, delivered: map[messageKey]struct{}{}, directSeen: map[string]map[uint64][32]byte{}, abortCh: make(chan struct{})}, nil
}

func (s *Session) Broadcast(ctx context.Context, payload []byte) error {
	s.outboundMu.Lock()
	defer s.outboundMu.Unlock()
	if len(payload) == 0 || len(payload) > s.config.MaxMessageBytes {
		return errors.New("broadcast payload is empty or oversized")
	}
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	s.broadcastSequence++
	sequence := s.broadcastSequence
	s.mu.Unlock()
	frame := s.base(KindBroadcast, s.config.LocalParty, sequence)
	frame.Origin = s.config.LocalParty
	frame.Payload = append([]byte(nil), payload...)
	if err := s.handle(ctx, s.config.LocalParty, frame); err != nil {
		return err
	}
	return s.fanout(ctx, frame)
}

func (s *Session) SendDirect(ctx context.Context, recipient string, payload []byte) error {
	s.outboundMu.Lock()
	defer s.outboundMu.Unlock()
	if recipient == s.config.LocalParty || len(payload) == 0 || len(payload) > s.config.MaxMessageBytes {
		return errors.New("invalid direct protocol message")
	}
	if _, ok := s.members[recipient]; !ok {
		return errors.New("direct message recipient is outside committee")
	}
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	s.directSequence++
	sequence := s.directSequence
	s.mu.Unlock()
	frame := s.base(KindDirect, recipient, sequence)
	frame.Payload = append([]byte(nil), payload...)
	return s.mesh.Send(ctx, recipient, frame)
}

// Receive must be called only after the transport has authenticated the mTLS
// certificate and verified that it represents authenticatedSender.
func (s *Session) Receive(ctx context.Context, authenticatedSender string, frame Frame) error {
	if authenticatedSender == "" || frame.Sender != authenticatedSender {
		return s.abort(errors.New("transport identity does not match protocol sender"))
	}
	if frame.SessionID != s.config.SessionID || frame.AttemptID != s.config.AttemptID || frame.KeyID != s.config.KeyID || frame.Epoch != s.config.Epoch {
		return s.abort(errors.New("protocol frame belongs to another session, attempt, key or epoch"))
	}
	if frame.Recipient != s.config.LocalParty {
		return s.abort(errors.New("protocol frame has the wrong recipient"))
	}
	if _, ok := s.members[authenticatedSender]; !ok {
		return s.abort(errors.New("protocol frame sender is outside committee"))
	}
	return s.handle(ctx, authenticatedSender, frame)
}

func (s *Session) handle(ctx context.Context, sender string, frame Frame) error {
	if frame.Sequence == 0 || frame.Sequence > s.config.MaxSequence {
		return s.abort(errors.New("protocol sequence is outside limits"))
	}
	switch frame.Kind {
	case KindBroadcast:
		if frame.Origin != sender || len(frame.Payload) == 0 || len(frame.Payload) > s.config.MaxMessageBytes || len(frame.Digest) != 0 {
			return s.abort(errors.New("malformed reliable-broadcast frame"))
		}
		if err := s.acceptCandidate(ctx, sender, frame); err != nil {
			return err
		}
	case KindEcho:
		if frame.Origin == "" || len(frame.Payload) != 0 || len(frame.Digest) != 32 {
			return s.abort(errors.New("malformed reliable-broadcast echo"))
		}
		if _, ok := s.members[frame.Origin]; !ok {
			return s.abort(errors.New("echo origin is outside committee"))
		}
		var digest [32]byte
		copy(digest[:], frame.Digest)
		return s.acceptEcho(ctx, sender, messageKey{frame.Origin, frame.Sequence}, digest)
	case KindDirect:
		if frame.Recipient != s.config.LocalParty || len(frame.Payload) == 0 || len(frame.Payload) > s.config.MaxMessageBytes || frame.Origin != "" || len(frame.Digest) != 0 {
			return s.abort(errors.New("malformed point-to-point frame"))
		}
		return s.acceptDirect(ctx, sender, frame)
	default:
		return s.abort(fmt.Errorf("unknown protocol frame kind %q", frame.Kind))
	}
	return nil
}

func (s *Session) acceptCandidate(ctx context.Context, sender string, frame Frame) error {
	key := messageKey{frame.Origin, frame.Sequence}
	digest := sha256.Sum256(frame.Payload)
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	if existing, ok := s.candidates[key]; ok && existing.digest != digest {
		s.mu.Unlock()
		return s.abort(errors.New("broadcast sender equivocated for one sequence"))
	}
	if _, ok := s.candidates[key]; !ok {
		s.candidates[key] = candidate{payload: append([]byte(nil), frame.Payload...), digest: digest}
	}
	if s.echoes[key] == nil {
		s.echoes[key] = map[string][32]byte{}
	}
	if old, ok := s.echoes[key][s.config.LocalParty]; ok && old != digest {
		s.mu.Unlock()
		return s.abort(errors.New("local broadcast echo conflicts with candidate"))
	}
	_, echoed := s.echoes[key][s.config.LocalParty]
	s.echoes[key][s.config.LocalParty] = digest
	s.mu.Unlock()
	if !echoed {
		if err := s.sendEcho(ctx, key, digest); err != nil {
			return s.abort(err)
		}
	}
	return s.tryDeliver(ctx, key)
}

func (s *Session) sendEcho(ctx context.Context, key messageKey, digest [32]byte) error {
	frame := s.base(KindEcho, "", key.Sequence)
	frame.Origin = key.Origin
	frame.Digest = append([]byte(nil), digest[:]...)
	return s.fanout(ctx, frame)
}

func (s *Session) acceptEcho(ctx context.Context, sender string, key messageKey, digest [32]byte) error {
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	if s.echoes[key] == nil {
		s.echoes[key] = map[string][32]byte{}
	}
	if old, ok := s.echoes[key][sender]; ok && old != digest {
		s.mu.Unlock()
		return s.abort(errors.New("committee member equivocated in reliable-broadcast echo"))
	}
	s.echoes[key][sender] = digest
	s.mu.Unlock()
	return s.tryDeliver(ctx, key)
}

func (s *Session) tryDeliver(ctx context.Context, key messageKey) error {
	s.mu.Lock()
	candidate, ok := s.candidates[key]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	echoes := s.echoes[key]
	if len(echoes) != len(s.members) {
		s.mu.Unlock()
		return nil
	}
	for member := range s.members {
		if echoes[member] != candidate.digest {
			s.mu.Unlock()
			return s.abort(errors.New("reliable-broadcast echo disagreement"))
		}
	}
	if _, done := s.delivered[key]; done {
		s.mu.Unlock()
		return nil
	}
	s.delivered[key] = struct{}{}
	payload := append([]byte(nil), candidate.payload...)
	origin := key.Origin
	s.mu.Unlock()
	if origin != s.config.LocalParty {
		if err := s.deliver(ctx, origin, payload, true); err != nil {
			return s.abort(fmt.Errorf("deliver reliable broadcast to TSS party: %w", err))
		}
	}
	return nil
}

func (s *Session) acceptDirect(ctx context.Context, sender string, frame Frame) error {
	digest := sha256.Sum256(frame.Payload)
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	if s.directSeen[sender] == nil {
		s.directSeen[sender] = map[uint64][32]byte{}
	}
	if old, ok := s.directSeen[sender][frame.Sequence]; ok {
		if old != digest {
			s.mu.Unlock()
			return s.abort(errors.New("direct message sequence was replayed with different contents"))
		}
		s.mu.Unlock()
		return nil
	}
	s.directSeen[sender][frame.Sequence] = digest
	s.mu.Unlock()
	if err := s.deliver(ctx, sender, append([]byte(nil), frame.Payload...), false); err != nil {
		return s.abort(fmt.Errorf("deliver point-to-point message to TSS party: %w", err))
	}
	return nil
}

func (s *Session) fanout(ctx context.Context, frame Frame) error {
	for member := range s.members {
		if member == s.config.LocalParty {
			continue
		}
		copyFrame := frame
		copyFrame.Recipient = member
		if err := s.mesh.Send(ctx, member, copyFrame); err != nil {
			return fmt.Errorf("send protocol frame to %s: %w", member, err)
		}
	}
	return nil
}

func (s *Session) base(kind Kind, recipient string, sequence uint64) Frame {
	return Frame{SessionID: s.config.SessionID, AttemptID: s.config.AttemptID, KeyID: s.config.KeyID, Epoch: s.config.Epoch, Kind: kind, Sender: s.config.LocalParty, Recipient: recipient, Sequence: sequence}
}

func (s *Session) abort(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted == nil {
		s.aborted = err
		close(s.abortCh)
	}
	return s.aborted
}

func (s *Session) Aborted() error { s.mu.Lock(); defer s.mu.Unlock(); return s.aborted }

func (s *Session) Done() <-chan struct{} { return s.abortCh }

func (s *Session) Abort(err error) error {
	if err == nil {
		err = errors.New("protocol session aborted")
	}
	return s.abort(err)
}
