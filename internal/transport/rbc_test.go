package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type memoryMesh struct {
	owner    string
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (m *memoryMesh) Send(ctx context.Context, to string, frame Frame) error {
	m.mu.RLock()
	target := m.sessions[to]
	m.mu.RUnlock()
	if target == nil {
		return errors.New("unknown peer")
	}
	return target.Receive(ctx, m.owner, frame)
}
func (m *memoryMesh) register(id string, session *Session) {
	m.mu.Lock()
	m.sessions[id] = session
	m.mu.Unlock()
}

func TestReliableBroadcastDeliversIdenticalFrameAndDirectMessage(t *testing.T) {
	ctx := context.Background()
	members := []string{"a", "b", "c"}
	meshes := map[string]*memoryMesh{}
	sessions := map[string]*Session{}
	delivered := map[string][]string{}
	var mu sync.Mutex
	for _, id := range members {
		meshes[id] = &memoryMesh{owner: id, sessions: map[string]*Session{}}
	}
	for _, id := range members {
		id := id
		session, err := NewSession(SessionConfig{SessionID: "session-1", AttemptID: "attempt-1", KeyID: "key-1", Epoch: 1, LocalParty: id, Members: members}, meshes[id], func(_ context.Context, from string, payload []byte, broadcast bool) error {
			mu.Lock()
			defer mu.Unlock()
			delivered[id] = append(delivered[id], from+":"+string(payload))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
	}
	for _, mesh := range meshes {
		mesh.mu.Lock()
		for id, session := range sessions {
			mesh.sessions[id] = session
		}
		mesh.mu.Unlock()
	}
	if err := meshes["a"].sessions["a"].Broadcast(ctx, []byte("same-round-message")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	for _, id := range []string{"b", "c"} {
		if len(delivered[id]) != 1 || delivered[id][0] != "a:same-round-message" {
			t.Fatalf("party %s received %v", id, delivered[id])
		}
	}
	mu.Unlock()
	if err := meshes["a"].sessions["a"].SendDirect(ctx, "c", []byte("secret-to-c")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(delivered["b"]) != 1 {
		t.Fatalf("point-to-point message leaked to B: %v", delivered["b"])
	}
	if len(delivered["c"]) != 2 || delivered["c"][1] != "a:secret-to-c" {
		t.Fatalf("C missed direct message: %v", delivered["c"])
	}
}

func TestBroadcastEquivocationFailsClosed(t *testing.T) {
	ctx := context.Background()
	members := []string{"a", "b", "c"}
	meshes := map[string]*memoryMesh{}
	sessions := map[string]*Session{}
	delivered := 0
	for _, id := range members {
		meshes[id] = &memoryMesh{owner: id, sessions: map[string]*Session{}}
	}
	for _, id := range members {
		id := id
		session, err := NewSession(SessionConfig{SessionID: "s", AttemptID: "a", KeyID: "k", Epoch: 1, LocalParty: id, Members: members}, meshes[id], func(context.Context, string, []byte, bool) error { delivered++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
	}
	for _, mesh := range meshes {
		mesh.mu.Lock()
		for id, session := range sessions {
			mesh.sessions[id] = session
		}
		mesh.mu.Unlock()
	}
	frame := Frame{SessionID: "s", AttemptID: "a", KeyID: "k", Epoch: 1, Kind: KindBroadcast, Sender: "a", Origin: "a", Sequence: 1, Payload: []byte("equivocation-left")}
	frame.Recipient = "b"
	if err := meshes["b"].sessions["b"].Receive(ctx, "a", frame); err != nil {
		t.Fatal(err)
	}
	frame.Recipient = "c"
	frame.Payload = []byte("equivocation-right")
	if err := meshes["c"].sessions["c"].Receive(ctx, "a", frame); err != nil {
		t.Fatal(err)
	}
	if delivered != 0 {
		t.Fatalf("equivocating message was delivered %d times", delivered)
	}
}

func TestSessionRejectsReplayAndCrossSessionFrames(t *testing.T) {
	mesh := &memoryMesh{owner: "a", sessions: map[string]*Session{}}
	session, err := NewSession(SessionConfig{SessionID: "s1", AttemptID: "a1", KeyID: "k1", Epoch: 1, LocalParty: "a", Members: []string{"a", "b", "c"}}, mesh, func(context.Context, string, []byte, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	frame := Frame{SessionID: "s0", AttemptID: "a1", KeyID: "k1", Epoch: 1, Kind: KindDirect, Sender: "b", Recipient: "a", Sequence: 1, Payload: []byte("stale")}
	if err := session.Receive(context.Background(), "b", frame); err == nil {
		t.Fatal("cross-session frame accepted")
	}
	if session.Aborted() == nil {
		t.Fatal("security violation did not abort session")
	}
}

func TestSessionRejectsMalformedCommitteeAndOutOfCommitteeRecipient(t *testing.T) {
	mesh := &memoryMesh{owner: "a", sessions: map[string]*Session{}}
	if _, err := NewSession(SessionConfig{SessionID: "s", AttemptID: "a", KeyID: "k", Epoch: 1, LocalParty: "a", Members: []string{"a"}}, mesh, func(context.Context, string, []byte, bool) error { return nil }); err == nil {
		t.Fatal("one-member committee accepted")
	}
	session, err := NewSession(SessionConfig{SessionID: "s", AttemptID: "a", KeyID: "k", Epoch: 1, LocalParty: "a", Members: []string{"a", "b", "c"}}, mesh, func(context.Context, string, []byte, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SendDirect(context.Background(), "outsider", []byte("x")); err == nil {
		t.Fatal("outside committee accepted")
	}
	if err := session.Broadcast(context.Background(), nil); err == nil {
		t.Fatal("empty broadcast accepted")
	}
}
