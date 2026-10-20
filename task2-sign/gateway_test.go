package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testGateway(t *testing.T) *Gateway {
	t.Helper()
	g, err := NewGateway(GatewayConfig{
		ListenHTTP: "127.0.0.1:0", WalletMetaDir: t.TempDir(), APIKey: "test-secret",
		Nodes: map[string]string{"node-1": "127.0.0.1:1", "node-2": "127.0.0.1:2", "node-3": "127.0.0.1:3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g.ctx = ctx
	return g
}

func TestGatewayHTTPAuthAndDigestValidation(t *testing.T) {
	g := testGateway(t)
	handler := g.Authorized(g.HTTPHandler())
	body := `{"wallet_id":"wallet-a","site_id":1,"index":2,"digest":"` + strings.Repeat("ab", 32) + `"}`
	request := func(key, content string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/sign", strings.NewReader(content))
		r.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("wrong", body).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthorized request status %d", got)
	}
	if got := request("test-secret", `{"wallet_id":"wallet-a","site_id":1,"index":2,"digest":"abc"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid digest status %d", got)
	}
	if got := request("test-secret", `{"wallet_id":"../escape","site_id":1,"index":2,"digest":"`+strings.Repeat("ab", 32)+`"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid wallet status %d", got)
	}
	if g.queued != 0 {
		t.Fatalf("invalid requests entered queue: %d", g.queued)
	}
}

func TestGatewayDefaultsAndCertificateFreeConfiguration(t *testing.T) {
	g := testGateway(t)
	if g.maxConcurrent != 5 || g.queueSize != 1000 {
		t.Fatalf("unexpected defaults: concurrent=%d queue=%d", g.maxConcurrent, g.queueSize)
	}
	if g.cfg.TLS.configured() || len(g.cfg.NodeFingerprints) != 0 {
		t.Fatal("default gateway configuration should not require certificates")
	}
}

func TestJobJSONStable(t *testing.T) {
	job := Job{ID: "id", Status: "queued"}
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	var got Job
	if err := json.Unmarshal(bytes.Clone(b), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != job.ID || got.Status != job.Status {
		t.Fatalf("job JSON roundtrip: %#v", got)
	}
}

func TestGatewayQueueSerializesSameWalletAndBoundsWaitingQueue(t *testing.T) {
	g := testGateway(t)
	ctx, cancel := context.WithCancel(context.Background())
	g.ctx = ctx
	t.Cleanup(cancel)
	g.queueSize = 2
	g.active = make(chan struct{}, 1)
	g.active <- struct{}{} // hold the only active slot so the worker cannot drain queued work

	newJob := func(id string) *queuedJob {
		return &queuedJob{job: Job{ID: id, Status: "queued"}, request: SignRequest{WalletID: "same-wallet"}}
	}
	if err := g.enqueue(newJob("first")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		g.mu.Lock()
		waiting := g.queued
		g.mu.Unlock()
		if waiting == 1 && len(g.queues["same-wallet"]) == 0 {
			break
		} // first request has moved to the worker but still waits for the global slot
		if time.Now().After(deadline) {
			t.Fatal("wallet worker did not take first job")
		}
		time.Sleep(time.Millisecond)
	}
	if err := g.enqueue(newJob("second")); err != nil {
		t.Fatal(err)
	}
	if err := g.enqueue(newJob("third")); err == nil {
		t.Fatal("queue accepted work beyond configured bound")
	}
	queue := g.queues["same-wallet"]
	if len(queue) != 1 || (<-queue).job.ID != "second" {
		t.Fatal("second request was not retained in the wallet FIFO queue")
	}
	if got := g.queued; got != 2 {
		t.Fatalf("queued count = %d, want 2 including work waiting for a slot", got)
	}
}
