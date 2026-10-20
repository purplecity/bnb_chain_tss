package sign

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v4/tss"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Node struct {
	cfg         NodeConfig
	mesh        *PeerMesh
	server      *grpc.Server
	mu          sync.Mutex
	prepared    map[string]*preparedSign
	walletLocks map[string]*sync.Mutex
	router      *sessionRouter
}

type preparedSign struct {
	frame   *LinkFrame
	wallet  *Wallet
	inbound chan PeerMessage
	started bool
	cancel  context.CancelFunc
}

type routedSession struct {
	walletID  string
	requestID string
	nodes     map[string]*tss.PartyID
	ch        chan PeerMessage
}

type sessionRouter struct {
	mu       sync.RWMutex
	sessions map[string]routedSession
}

func newSessionRouter() *sessionRouter {
	return &sessionRouter{sessions: make(map[string]routedSession)}
}
func (r *sessionRouter) register(sessionID string, s routedSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[sessionID]; ok {
		return errors.New("session ID is already active")
	}
	r.sessions[sessionID] = s
	return nil
}
func (r *sessionRouter) remove(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
}
func (r *sessionRouter) deliver(f *LinkFrame) error {
	r.mu.RLock()
	s, ok := r.sessions[f.SessionID]
	r.mu.RUnlock()
	if !ok {
		return errors.New("peer frame has no prepared session")
	}
	if f.WalletID != s.walletID || f.RequestID != s.requestID || f.To == "" {
		return errors.New("peer frame metadata does not match prepared session")
	}
	party := s.nodes[f.From]
	if party == nil {
		return errors.New("peer frame sender is not in wallet roster")
	}
	select {
	case s.ch <- PeerMessage{Frame: f, Party: party}:
		return nil
	default:
		return errors.New("signing session input buffer is full")
	}
}

func NewNode(cfg NodeConfig) (*Node, error) {
	if !safeWalletID.MatchString(cfg.NodeID) {
		return nil, errors.New("invalid node_id")
	}
	if cfg.Listen == "" || cfg.WalletDir == "" {
		return nil, errors.New("listen and wallet_dir are required")
	}
	if len(cfg.Peers) != 2 {
		return nil, errors.New("each signer node must configure exactly two peers")
	}
	tlsEnabled := cfg.TLS.configured()
	if tlsEnabled {
		if len(cfg.PeerFingerprints) != 2 {
			return nil, errors.New("TLS requires certificate pins for both peers")
		}
		if _, err := normalizeFingerprint(cfg.GatewayFingerprint); err != nil {
			return nil, fmt.Errorf("gateway_fingerprint: %w", err)
		}
	} else if len(cfg.PeerFingerprints) != 0 || cfg.GatewayFingerprint != "" {
		return nil, errors.New("certificate pins require TLS to be configured")
	}
	for peerID, endpoint := range cfg.Peers {
		if peerID == cfg.NodeID {
			return nil, errors.New("peer list contains local node")
		}
		if endpoint == "" {
			return nil, fmt.Errorf("missing endpoint for peer %s", peerID)
		}
		if tlsEnabled {
			pin, ok := cfg.PeerFingerprints[peerID]
			if !ok {
				return nil, fmt.Errorf("missing certificate fingerprint for peer %s", peerID)
			}
			if _, err := normalizeFingerprint(pin); err != nil {
				return nil, fmt.Errorf("peer pin for %s: %w", peerID, err)
			}
		}
	}
	serverOptions := []grpc.ServerOption{grpc.MaxRecvMsgSize(5 << 20), grpc.MaxSendMsgSize(5 << 20)}
	if tlsEnabled {
		serverTLS, err := cfg.TLS.serverConfig()
		if err != nil {
			return nil, err
		}
		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	s := grpc.NewServer(serverOptions...)
	n := &Node{cfg: cfg, mesh: NewPeerMesh(cfg), server: s, prepared: make(map[string]*preparedSign), walletLocks: make(map[string]*sync.Mutex), router: newSessionRouter()}
	registerSignerRPC(s, n)
	return n, nil
}

func (n *Node) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", n.cfg.Listen)
	if err != nil {
		return err
	}
	n.mesh.Run(ctx)
	go func() { <-ctx.Done(); n.server.GracefulStop() }()
	err = n.server.Serve(listener)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

func (n *Node) PeerChannel(stream peerChannelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.Type != "HELLO" || first.From == "" || first.From == n.cfg.NodeID {
		return errors.New("invalid peer handshake")
	}
	if _, ok := n.cfg.Peers[first.From]; !ok {
		return errors.New("peer ID is not allowed")
	}
	if n.cfg.TLS.configured() {
		state, err := tlsStateFromContext(stream.Context())
		if err != nil {
			return err
		}
		fingerprint, err := fingerprintFromTLS(state)
		if err != nil {
			return err
		}
		want, _ := normalizeFingerprint(n.cfg.PeerFingerprints[first.From])
		if fingerprint != want {
			return errors.New("peer certificate fingerprint mismatch")
		}
	}
	if err := stream.Send(&LinkFrame{Type: "HELLO_ACK", From: n.cfg.NodeID, To: first.From}); err != nil {
		return err
	}
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := validateFramePayload(frame); err != nil {
			return err
		}
		if frame.Type != "TSS" || frame.From != first.From || frame.To != n.cfg.NodeID {
			return errors.New("invalid peer protocol frame")
		}
		if err := n.router.deliver(frame); err != nil {
			return err
		}
	}
}

func (n *Node) ControlChannel(stream controlChannelServer) error {
	if n.cfg.TLS.configured() {
		state, err := tlsStateFromContext(stream.Context())
		if err != nil {
			return err
		}
		want, _ := normalizeFingerprint(n.cfg.GatewayFingerprint)
		got, err := fingerprintFromTLS(state)
		if err != nil {
			return err
		}
		if got != want {
			return errors.New("gateway client certificate fingerprint mismatch")
		}
	}
	owned := make(map[string]*LinkFrame)
	defer func() {
		for _, frame := range owned {
			n.cancelSign(frame)
		}
	}()
	sender := &sendGuard{send: stream.Send}
	if err := sender.Send(&LinkFrame{Type: "CONTROL_READY", From: n.cfg.NodeID}); err != nil {
		return err
	}
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if frame == nil {
			return errors.New("empty control frame")
		}
		switch frame.Type {
		case "PREPARE_SIGN":
			if err := n.prepareSign(frame); err != nil {
				_ = sender.Send(n.controlError(frame, err))
				continue
			}
			owned[frame.RequestID] = copyFrame(frame)
			if err := sender.Send(&LinkFrame{Type: "SIGN_PREPARED", From: n.cfg.NodeID, RequestID: frame.RequestID, SessionID: frame.SessionID}); err != nil {
				return err
			}
		case "START_SIGN":
			signCtx, cancel := context.WithTimeout(stream.Context(), 5*time.Minute)
			p, err := n.startSign(frame, cancel)
			if err != nil {
				cancel()
				_ = sender.Send(n.controlError(frame, err))
				continue
			}
			if err := sender.Send(&LinkFrame{Type: "SIGN_STARTED", From: n.cfg.NodeID, RequestID: frame.RequestID, SessionID: frame.SessionID}); err != nil {
				cancel()
				return err
			}
			go n.runPreparedSign(signCtx, p, sender)
		case "CANCEL_SIGN":
			n.cancelSign(frame)
			delete(owned, frame.RequestID)
		default:
			_ = sender.Send(n.controlError(frame, errors.New("unsupported control frame")))
		}
	}
}

func (n *Node) prepareSign(frame *LinkFrame) error {
	if frame.RequestID == "" || frame.SessionID == "" || len(frame.Digest) != 32 || len(frame.Nonce) != 32 || newBig(frame.Nonce).Sign() == 0 {
		return errors.New("request/session IDs, 32-byte digest and non-zero 32-byte nonce are required")
	}
	if frame.SiteID >= 1<<31 || frame.Index >= 1<<31 {
		return errors.New("site_id and index must be non-hardened indices below 2^31")
	}
	wallet, err := LoadWallet(n.cfg.WalletDir, frame.WalletID, n.cfg.NodeID)
	if err != nil {
		return err
	}
	if _, _, err := deriveChild(wallet, frame.SiteID, frame.Index); err != nil {
		return err
	}
	nodes := make(map[string]*tss.PartyID, len(wallet.PartyIDs))
	for _, id := range wallet.PartyIDs {
		nodes[id.Id] = id
	}
	inbound := make(chan PeerMessage, 2048)
	n.mu.Lock()
	if old, ok := n.prepared[frame.RequestID]; ok {
		n.mu.Unlock()
		if old.frame.SessionID == frame.SessionID && sameSignRequest(old.frame, frame) {
			return nil
		}
		return errors.New("request ID has already been prepared with different parameters")
	}
	n.mu.Unlock()
	if err := n.router.register(frame.SessionID, routedSession{walletID: frame.WalletID, requestID: frame.RequestID, nodes: nodes, ch: inbound}); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.prepared[frame.RequestID]; exists {
		n.router.remove(frame.SessionID)
		return errors.New("request ID preparation raced with another request")
	}
	n.prepared[frame.RequestID] = &preparedSign{frame: copyFrame(frame), wallet: wallet, inbound: inbound}
	return nil
}

func (n *Node) startSign(frame *LinkFrame, cancel context.CancelFunc) (*preparedSign, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	p, ok := n.prepared[frame.RequestID]
	if !ok {
		return nil, errors.New("sign request was not prepared")
	}
	if p.frame.SessionID != frame.SessionID || !sameSignRequest(p.frame, frame) {
		return nil, errors.New("start request does not match prepared request")
	}
	if p.started {
		return nil, errors.New("sign request was already started")
	}
	p.started = true
	p.cancel = cancel
	return p, nil
}

func (n *Node) cancelSign(frame *LinkFrame) {
	n.mu.Lock()
	p := n.prepared[frame.RequestID]
	if p == nil || p.frame.SessionID != frame.SessionID {
		n.mu.Unlock()
		return
	}
	if p.cancel != nil {
		p.cancel()
		n.mu.Unlock()
		return
	}
	delete(n.prepared, frame.RequestID)
	n.mu.Unlock()
	n.router.remove(frame.SessionID)
}

func (n *Node) runPreparedSign(ctx context.Context, p *preparedSign, sender *sendGuard) {
	frame := p.frame
	if p.cancel != nil {
		defer p.cancel()
	}
	lock := n.walletLock(frame.WalletID)
	lock.Lock()
	defer lock.Unlock()
	defer func() {
		n.router.remove(frame.SessionID)
		n.mu.Lock()
		delete(n.prepared, frame.RequestID)
		n.mu.Unlock()
	}()
	sig, err := RunSigningParty(ctx, n.cfg.NodeID, p.wallet, frame.RequestID, frame.SessionID, frame.Digest, frame.Nonce, frame.SiteID, frame.Index, p.inbound, n.mesh.Send)
	if err != nil {
		_ = sender.Send(&LinkFrame{Type: "SIGN_RESULT", From: n.cfg.NodeID, RequestID: frame.RequestID, SessionID: frame.SessionID, Error: err.Error()})
		return
	}
	_ = sender.Send(&LinkFrame{Type: "SIGN_RESULT", From: n.cfg.NodeID, RequestID: frame.RequestID, SessionID: frame.SessionID, Signature: sig.Signature, Recovery: sig.SignatureRecovery, R: sig.R, S: sig.S, PublicKey: mustChildPublic(p.wallet, frame.SiteID, frame.Index)})
}

func (n *Node) walletLock(walletID string) *sync.Mutex {
	n.mu.Lock()
	defer n.mu.Unlock()
	lock := n.walletLocks[walletID]
	if lock == nil {
		lock = &sync.Mutex{}
		n.walletLocks[walletID] = lock
	}
	return lock
}
func (n *Node) controlError(frame *LinkFrame, err error) *LinkFrame {
	return &LinkFrame{Type: "ERROR", From: n.cfg.NodeID, RequestID: frame.RequestID, SessionID: frame.SessionID, Error: err.Error()}
}
func sameSignRequest(a, b *LinkFrame) bool {
	return a.WalletID == b.WalletID && a.RequestID == b.RequestID && a.SessionID == b.SessionID && string(a.Digest) == string(b.Digest) && string(a.Nonce) == string(b.Nonce) && a.SiteID == b.SiteID && a.Index == b.Index
}
func copyFrame(f *LinkFrame) *LinkFrame {
	c := *f
	c.Digest = append([]byte(nil), f.Digest...)
	c.Nonce = append([]byte(nil), f.Nonce...)
	return &c
}
func newBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func deriveChild(wallet *Wallet, siteID, index uint32) (*ecdsa.PublicKey, *big.Int, error) {
	result, tweak, err := derive.Derive(wallet.Meta, siteID, index)
	if err != nil {
		return nil, nil, err
	}
	b, err := hex.DecodeString(result.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pub, err := gethcrypto.UnmarshalPubkey(b)
	if err != nil {
		return nil, nil, err
	}
	return pub, tweak, nil
}
func mustChildPublic(wallet *Wallet, siteID, index uint32) string {
	p, _, err := deriveChild(wallet, siteID, index)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(gethcrypto.FromECDSAPub(p))
}
