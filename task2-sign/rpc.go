package sign

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

const (
	peerMethod    = "/bnbtss.v1.Signer/PeerChannel"
	controlMethod = "/bnbtss.v1.Signer/ControlChannel"
)

// This repository uses a small JSON codec over gRPC to keep the wire schema
// readable without generated code. Cryptographic protocol payloads remain the
// protobuf bytes emitted by tss-lib and are carried in Payload.
type jsonCodec struct{}

func (jsonCodec) Name() string                    { return "json" }
func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func init()                                       { encoding.RegisterCodec(jsonCodec{}) }

type LinkFrame struct {
	Type      string `json:"type"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	WalletID  string `json:"wallet_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Broadcast bool   `json:"broadcast,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Digest    []byte `json:"digest,omitempty"`
	Nonce     []byte `json:"nonce,omitempty"`
	SiteID    uint32 `json:"site_id,omitempty"`
	Index     uint32 `json:"index,omitempty"`
	Error     string `json:"error,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	Recovery  []byte `json:"recovery,omitempty"`
	R         []byte `json:"r,omitempty"`
	S         []byte `json:"s,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

type peerChannelClient interface {
	Send(*LinkFrame) error
	Recv() (*LinkFrame, error)
}
type peerChannelServer interface {
	Context() context.Context
	Send(*LinkFrame) error
	Recv() (*LinkFrame, error)
}
type controlChannelClient interface {
	Send(*LinkFrame) error
	Recv() (*LinkFrame, error)
}
type controlChannelServer interface {
	Context() context.Context
	Send(*LinkFrame) error
	Recv() (*LinkFrame, error)
}

type peerClient struct{ grpc.ClientStream }

func (s *peerClient) Send(m *LinkFrame) error { return s.SendMsg(m) }
func (s *peerClient) Recv() (*LinkFrame, error) {
	m := new(LinkFrame)
	if err := s.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type peerServer struct{ grpc.ServerStream }

func (s *peerServer) Send(m *LinkFrame) error { return s.SendMsg(m) }
func (s *peerServer) Recv() (*LinkFrame, error) {
	m := new(LinkFrame)
	if err := s.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type controlClient struct{ grpc.ClientStream }

func (s *controlClient) Send(m *LinkFrame) error { return s.SendMsg(m) }
func (s *controlClient) Recv() (*LinkFrame, error) {
	m := new(LinkFrame)
	if err := s.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type controlServer struct{ grpc.ServerStream }

func (s *controlServer) Send(m *LinkFrame) error { return s.SendMsg(m) }
func (s *controlServer) Recv() (*LinkFrame, error) {
	m := new(LinkFrame)
	if err := s.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type signerRPCServer interface {
	PeerChannel(peerChannelServer) error
	ControlChannel(controlChannelServer) error
}

func registerSignerRPC(s *grpc.Server, srv signerRPCServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "bnbtss.v1.Signer",
		HandlerType: (*signerRPCServer)(nil),
		Streams: []grpc.StreamDesc{
			{StreamName: "PeerChannel", Handler: peerHandler, ServerStreams: true, ClientStreams: true},
			{StreamName: "ControlChannel", Handler: controlHandler, ServerStreams: true, ClientStreams: true},
		},
	}, srv)
}

func peerHandler(srv any, stream grpc.ServerStream) error {
	return srv.(signerRPCServer).PeerChannel(&peerServer{stream})
}
func controlHandler(srv any, stream grpc.ServerStream) error {
	return srv.(signerRPCServer).ControlChannel(&controlServer{stream})
}

func openPeer(ctx context.Context, conn *grpc.ClientConn) (peerChannelClient, error) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "PeerChannel", ServerStreams: true, ClientStreams: true}, peerMethod, grpc.StaticMethod(), grpc.CallContentSubtype("json"))
	if err != nil {
		return nil, err
	}
	return &peerClient{stream}, nil
}
func openControl(ctx context.Context, conn *grpc.ClientConn) (controlChannelClient, error) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "ControlChannel", ServerStreams: true, ClientStreams: true}, controlMethod, grpc.StaticMethod(), grpc.CallContentSubtype("json"))
	if err != nil {
		return nil, err
	}
	return &controlClient{stream}, nil
}

type sendGuard struct {
	mu   sync.Mutex
	send func(*LinkFrame) error
}

func (g *sendGuard) Send(m *LinkFrame) error { g.mu.Lock(); defer g.mu.Unlock(); return g.send(m) }

func validateFramePayload(f *LinkFrame) error {
	if f == nil {
		return errors.New("empty gRPC frame")
	}
	if len(f.Payload) > 4<<20 {
		return errors.New("protocol frame exceeds 4 MiB")
	}
	return nil
}
