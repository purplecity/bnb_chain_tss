package sign

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
)

type peerConn struct {
	conn   *grpc.ClientConn
	stream peerChannelClient
	sendMu sync.Mutex
}

type PeerMesh struct {
	selfID    string
	endpoints map[string]string
	tlsFiles  TLSFiles
	pins      map[string]string
	mu        sync.RWMutex
	conns     map[string]*peerConn
}

func NewPeerMesh(cfg NodeConfig) *PeerMesh {
	return &PeerMesh{selfID: cfg.NodeID, endpoints: cfg.Peers, tlsFiles: cfg.TLS, pins: cfg.PeerFingerprints, conns: make(map[string]*peerConn)}
}

func (m *PeerMesh) Run(ctx context.Context) {
	for peerID, endpoint := range m.endpoints {
		if peerID == m.selfID {
			continue
		}
		go m.connectLoop(ctx, peerID, endpoint)
	}
}

func (m *PeerMesh) connectLoop(ctx context.Context, peerID, endpoint string) {
	delay := time.Second
	for ctx.Err() == nil {
		var transport credentials.TransportCredentials = insecure.NewCredentials()
		var err error
		if m.tlsFiles.configured() {
			var tlsCfg *tls.Config
			tlsCfg, err = m.tlsFiles.clientConfig(m.pins[peerID])
			if err == nil {
				transport = credentials.NewTLS(tlsCfg)
			}
		}
		if err == nil {
			var conn *grpc.ClientConn
			dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			conn, err = grpc.DialContext(dialCtx, endpoint, grpc.WithTransportCredentials(transport), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
			cancel()
			if err == nil {
				streamCtx, streamCancel := context.WithCancel(ctx)
				stream, openErr := openPeer(streamCtx, conn)
				if openErr == nil {
					openErr = stream.Send(&LinkFrame{Type: "HELLO", From: m.selfID})
				}
				var current *peerConn
				if openErr == nil {
					var ack *LinkFrame
					ack, openErr = stream.Recv()
					if openErr == nil && (ack.Type != "HELLO_ACK" || ack.From != peerID || ack.To != m.selfID) {
						openErr = errors.New("peer handshake identity mismatch")
					}
					if openErr == nil {
						current = &peerConn{conn: conn, stream: stream}
						m.set(peerID, current)
					}
				}
				if openErr == nil {
					_, recvErr := stream.Recv()
					openErr = recvErr
				}
				if current != nil {
					m.remove(peerID, current)
				}
				streamCancel()
				_ = conn.Close()
				err = openErr
			}
		}
		if ctx.Err() != nil {
			return
		}
		_ = err
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if delay < 15*time.Second {
			delay *= 2
		}
	}
}

func (m *PeerMesh) set(id string, c *peerConn) { m.mu.Lock(); defer m.mu.Unlock(); m.conns[id] = c }
func (m *PeerMesh) remove(id string, c *peerConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conns[id] == c {
		delete(m.conns, id)
	}
}

func (m *PeerMesh) Send(ctx context.Context, frame *LinkFrame) error {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		m.mu.RLock()
		conn := m.conns[frame.To]
		m.mu.RUnlock()
		if conn != nil {
			conn.sendMu.Lock()
			err := conn.stream.Send(frame)
			conn.sendMu.Unlock()
			if err == nil {
				return nil
			}
			m.remove(frame.To, conn)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("no live gRPC connection to peer %s", frame.To)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func tlsStateFromContext(ctx context.Context) (tls.ConnectionState, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return tls.ConnectionState{}, errors.New("gRPC connection has no peer information")
	}
	switch info := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		return info.State, nil
	case *credentials.TLSInfo:
		return info.State, nil
	default:
		return tls.ConnectionState{}, errors.New("gRPC connection has no verified TLS peer")
	}
}
