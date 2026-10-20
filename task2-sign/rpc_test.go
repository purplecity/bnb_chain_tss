package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

type rpcProbe struct{}

func (rpcProbe) PeerChannel(stream peerChannelServer) error {
	frame, err := stream.Recv()
	if err != nil {
		return err
	}
	frame.Type = "ACK"
	return stream.Send(frame)
}
func (rpcProbe) ControlChannel(stream controlChannelServer) error {
	frame, err := stream.Recv()
	if err != nil {
		return err
	}
	frame.Type = "ACK"
	return stream.Send(frame)
}

func TestLinkFrameJSONCodec(t *testing.T) {
	want := &LinkFrame{Type: "TSS", From: "node-1", To: "node-2", WalletID: "wallet", RequestID: "request", SessionID: "session", Broadcast: true, Payload: []byte{0, 1, 2, 255}, Digest: bytes.Repeat([]byte{3}, 32), Nonce: bytes.Repeat([]byte{4}, 32), SiteID: 7, Index: 9, Signature: []byte{5}, Recovery: []byte{1}, R: []byte{6}, S: []byte{7}, PublicKey: "pub"}
	b, err := (jsonCodec{}).Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got LinkFrame
	if err := (jsonCodec{}).Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.From != want.From || got.To != want.To || got.WalletID != want.WalletID || got.RequestID != want.RequestID || got.SessionID != want.SessionID || got.SiteID != want.SiteID || got.Index != want.Index || !bytes.Equal(got.Payload, want.Payload) || !bytes.Equal(got.Digest, want.Digest) || !bytes.Equal(got.Nonce, want.Nonce) || !bytes.Equal(got.Signature, want.Signature) {
		t.Fatalf("JSON codec changed frame: %#v", got)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["payload"].(string); !ok {
		t.Fatal("binary protocol payload must use JSON base64")
	}
}

func TestGRPCBidirectionalStreams(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	registerSignerRPC(server, rpcProbe{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, listener.Addr().String(), grpc.WithInsecure(), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for name, open := range map[string]func(context.Context, *grpc.ClientConn) (controlChannelClient, error){"peer": func(c context.Context, conn *grpc.ClientConn) (controlChannelClient, error) {
		s, e := openPeer(c, conn)
		if e != nil {
			return nil, e
		}
		return s, nil
	}, "control": openControl} {
		stream, err := open(ctx, conn)
		if err != nil {
			t.Fatalf("%s stream open: %v", name, err)
		}
		want := &LinkFrame{Type: "PROBE", Payload: []byte{1, 2, 3}}
		if err := stream.Send(want); err != nil {
			t.Fatalf("%s send: %v", name, err)
		}
		got, err := stream.Recv()
		if err != nil {
			t.Fatalf("%s recv: %v", name, err)
		}
		if got.Type != "ACK" || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("%s got %#v", name, got)
		}
	}
}

func TestValidateFramePayloadLimit(t *testing.T) {
	if err := validateFramePayload(&LinkFrame{Payload: make([]byte, 4<<20)}); err != nil {
		t.Fatal(err)
	}
	if err := validateFramePayload(&LinkFrame{Payload: make([]byte, (4<<20)+1)}); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := validateFramePayload(nil); err == nil {
		t.Fatal("nil frame accepted")
	}
}
