package sign

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type SignRequest struct {
	WalletID string `json:"wallet_id"`
	SiteID   uint32 `json:"site_id"`
	Index    uint32 `json:"index"`
	Digest   string `json:"digest"`
}

type SignResult struct {
	RequestID  string `json:"request_id"`
	WalletID   string `json:"wallet_id"`
	SiteID     uint32 `json:"site_id"`
	Index      uint32 `json:"index"`
	Path       string `json:"path"`
	Signature  string `json:"signature"`
	RecoveryID string `json:"recovery_id"`
	R          string `json:"r"`
	S          string `json:"s"`
}

type Job struct {
	ID     string      `json:"id"`
	Status string      `json:"status"`
	Result *SignResult `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type queuedJob struct {
	job       Job
	request   SignRequest
	digest    []byte
	sessionID string
	nonce     []byte
}

type gatewayNode struct {
	conn   *grpc.ClientConn
	stream controlChannelClient
	sender *sendGuard
}

type nodeResponse struct {
	nodeID string
	frame  *LinkFrame
}

type Gateway struct {
	cfg           GatewayConfig
	ctx           context.Context
	mu            sync.Mutex
	nodes         map[string]*gatewayNode
	waiters       map[string]chan nodeResponse
	jobs          map[string]*Job
	queues        map[string]chan *queuedJob
	queued        int
	queueSize     int
	maxConcurrent int
	active        chan struct{}
}

func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.ListenHTTP == "" || cfg.WalletMetaDir == "" || cfg.APIKey == "" {
		return nil, errors.New("listen_http, wallet_meta_dir and api_key are required")
	}
	if len(cfg.Nodes) != 3 {
		return nil, errors.New("gateway must configure three signer nodes")
	}
	tlsEnabled := cfg.TLS.configured()
	if tlsEnabled && len(cfg.NodeFingerprints) != 3 {
		return nil, errors.New("TLS requires certificate pins for all three signer nodes")
	}
	if !tlsEnabled && len(cfg.NodeFingerprints) != 0 {
		return nil, errors.New("signer certificate pins require TLS to be configured")
	}
	for id := range cfg.Nodes {
		if !safeWalletID.MatchString(id) {
			return nil, fmt.Errorf("invalid signer node ID %s", id)
		}
		if tlsEnabled {
			pin, ok := cfg.NodeFingerprints[id]
			if !ok {
				return nil, fmt.Errorf("missing certificate fingerprint for %s", id)
			}
			if _, err := normalizeFingerprint(pin); err != nil {
				return nil, fmt.Errorf("node pin %s: %w", id, err)
			}
		}
	}
	if (cfg.APICertificate == "") != (cfg.APIPrivateKey == "") {
		return nil, errors.New("api_certificate and api_private_key must be configured together")
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 5
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	return &Gateway{cfg: cfg, nodes: make(map[string]*gatewayNode), waiters: make(map[string]chan nodeResponse), jobs: make(map[string]*Job), queues: make(map[string]chan *queuedJob), queueSize: cfg.QueueSize, maxConcurrent: cfg.MaxConcurrent, active: make(chan struct{}, cfg.MaxConcurrent)}, nil
}

func (g *Gateway) Connect(ctx context.Context) error {
	g.ctx = ctx
	for id, endpoint := range g.cfg.Nodes {
		if err := g.connectNode(ctx, id, endpoint); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) connectNode(ctx context.Context, id, endpoint string) error {
	var transport credentials.TransportCredentials = insecure.NewCredentials()
	if g.cfg.TLS.configured() {
		tlsCfg, err := g.cfg.TLS.clientConfig(g.cfg.NodeFingerprints[id])
		if err != nil {
			return err
		}
		transport = credentials.NewTLS(tlsCfg)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, endpoint, grpc.WithTransportCredentials(transport), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
	if err != nil {
		return fmt.Errorf("connect signer %s: %w", id, err)
	}
	stream, err := openControl(ctx, conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("open control stream to %s: %w", id, err)
	}
	responseCh := make(chan nodeResponse, 32)
	client := &gatewayNode{conn: conn, stream: stream}
	client.sender = &sendGuard{send: stream.Send}
	g.mu.Lock()
	g.nodes[id] = client
	g.mu.Unlock()
	go g.readNode(ctx, id, stream, responseCh)
	// Wait for a server-side readiness acknowledgment before considering the
	// long-lived stream established.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp := <-responseCh:
		if resp.frame.Type != "CONTROL_READY" || resp.frame.From != id {
			return fmt.Errorf("signer %s failed control handshake", id)
		}
	case <-time.After(15 * time.Second):
		return fmt.Errorf("signer %s control handshake timed out", id)
	}
	return nil
}

func (g *Gateway) readNode(ctx context.Context, id string, stream controlChannelClient, initial chan nodeResponse) {
	first := true
	for {
		frame, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				g.failNodeWaiters(id, err)
			}
			return
		}
		resp := nodeResponse{nodeID: id, frame: frame}
		if first {
			first = false
			initial <- resp
			continue
		}
		g.mu.Lock()
		waiter := g.waiters[frame.RequestID]
		g.mu.Unlock()
		if waiter != nil {
			select {
			case waiter <- resp:
			default:
			}
		}
	}
}

func (g *Gateway) failNodeWaiters(nodeID string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, ch := range g.waiters {
		select {
		case ch <- nodeResponse{nodeID: nodeID, frame: &LinkFrame{Type: "ERROR", From: nodeID, Error: "gRPC stream closed: " + err.Error()}}:
		default:
		}
	}
}

func (g *Gateway) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", g.handleSubmit)
	mux.HandleFunc("GET /v1/jobs/{job_id}", g.handleJob)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func (g *Gateway) Authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-API-Key")
		if len(provided) != len(g.cfg.APIKey) || subtle.ConstantTimeCompare([]byte(provided), []byte(g.cfg.APIKey)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid request JSON", http.StatusBadRequest)
		return
	}
	if !safeWalletID.MatchString(req.WalletID) || req.SiteID >= 1<<31 || req.Index >= 1<<31 {
		http.Error(w, "invalid wallet_id, site_id or index", http.StatusBadRequest)
		return
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(req.Digest, "0x"))
	if err != nil || len(digest) != 32 {
		http.Error(w, "digest must be 32-byte hex", http.StatusBadRequest)
		return
	}
	id, err := randomID()
	if err != nil {
		http.Error(w, "could not allocate request ID", http.StatusInternalServerError)
		return
	}
	session, err := randomID()
	if err != nil {
		http.Error(w, "could not allocate session ID", http.StatusInternalServerError)
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "could not allocate session nonce", http.StatusInternalServerError)
		return
	}
	if new(big.Int).SetBytes(nonce).Sign() == 0 {
		nonce[31] = 1
	}
	queued := &queuedJob{job: Job{ID: id, Status: "queued"}, request: req, digest: digest, sessionID: session, nonce: nonce}
	if err := g.enqueue(queued); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusAccepted, queued.job)
}

func (g *Gateway) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("job_id")
	g.mu.Lock()
	job := g.jobs[id]
	if job != nil {
		copy := *job
		job = &copy
	}
	g.mu.Unlock()
	if job == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (g *Gateway) enqueue(job *queuedJob) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.queued >= g.queueSize {
		return errors.New("signing queue is full")
	}
	queue := g.queues[job.request.WalletID]
	if queue == nil {
		queue = make(chan *queuedJob, g.queueSize)
		g.queues[job.request.WalletID] = queue
		go g.walletWorker(job.request.WalletID, queue)
	}
	select {
	case queue <- job:
		g.queued++
		stored := job.job
		g.jobs[job.job.ID] = &stored
		return nil
	default:
		return errors.New("signing queue is full")
	}
}

func (g *Gateway) walletWorker(walletID string, queue <-chan *queuedJob) {
	for {
		var job *queuedJob
		select {
		case <-g.ctx.Done():
			return
		case job = <-queue:
		}
		select {
		case g.active <- struct{}{}:
		case <-g.ctx.Done():
			g.mu.Lock()
			g.queued--
			if stored := g.jobs[job.job.ID]; stored != nil {
				stored.Status = "failed"
				stored.Error = "gateway shutting down"
			}
			g.mu.Unlock()
			return
		}
		g.mu.Lock()
		g.queued--
		if stored := g.jobs[job.job.ID]; stored != nil {
			stored.Status = "processing"
		}
		g.mu.Unlock()
		result, err := g.execute(job)
		<-g.active
		g.mu.Lock()
		if stored := g.jobs[job.job.ID]; stored != nil {
			if err != nil {
				stored.Status = "failed"
				stored.Error = err.Error()
			} else {
				stored.Status = "succeeded"
				stored.Result = result
			}
		}
		g.mu.Unlock()
	}
}

func (g *Gateway) execute(job *queuedJob) (*SignResult, error) {
	ctx, cancel := context.WithTimeout(g.ctx, 5*time.Minute)
	defer cancel()
	wallet, err := g.loadPublicWallet(job.request.WalletID)
	if err != nil {
		return nil, err
	}
	derived, _, err := derive.Derive(wallet, job.request.SiteID, job.request.Index)
	if err != nil {
		return nil, err
	}
	pubBytes, _ := hex.DecodeString(derived.PublicKey)
	pub, err := gethcrypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return nil, err
	}
	waiter := make(chan nodeResponse, 24)
	g.mu.Lock()
	g.waiters[job.job.ID] = waiter
	nodes := make(map[string]*gatewayNode, len(g.nodes))
	for id, node := range g.nodes {
		nodes[id] = node
	}
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.waiters, job.job.ID); g.mu.Unlock() }()
	if len(nodes) != 3 {
		return nil, errors.New("not connected to all three signer nodes")
	}
	completed := false
	defer func() {
		if !completed {
			_ = g.sendAll(nodes, func(_ string) *LinkFrame {
				return &LinkFrame{Type: "CANCEL_SIGN", RequestID: job.job.ID, SessionID: job.sessionID}
			})
		}
	}()
	requestFrame := &LinkFrame{WalletID: job.request.WalletID, RequestID: job.job.ID, SessionID: job.sessionID, Digest: job.digest, Nonce: job.nonce, SiteID: job.request.SiteID, Index: job.request.Index}
	if err := g.sendAll(nodes, func(_ string) *LinkFrame { f := *requestFrame; f.Type = "PREPARE_SIGN"; return &f }); err != nil {
		return nil, err
	}
	if _, err := g.awaitNodeResponses(ctx, waiter, job.job.ID, job.sessionID, "SIGN_PREPARED", nodes); err != nil {
		return nil, err
	}
	if err := g.sendAll(nodes, func(_ string) *LinkFrame { f := *requestFrame; f.Type = "START_SIGN"; return &f }); err != nil {
		return nil, err
	}
	if _, err := g.awaitNodeResponses(ctx, waiter, job.job.ID, job.sessionID, "SIGN_STARTED", nodes); err != nil {
		return nil, err
	}
	responses, err := g.awaitNodeResponses(ctx, waiter, job.job.ID, job.sessionID, "SIGN_RESULT", nodes)
	if err != nil {
		return nil, err
	}
	var canonical *LinkFrame
	for id, frame := range responses {
		if frame.Error != "" {
			return nil, fmt.Errorf("signer %s: %s", id, frame.Error)
		}
		if canonical == nil {
			canonical = frame
			continue
		}
		if string(canonical.Signature) != string(frame.Signature) || string(canonical.R) != string(frame.R) || string(canonical.S) != string(frame.S) || string(canonical.Recovery) != string(frame.Recovery) {
			return nil, errors.New("signer nodes returned inconsistent threshold signatures")
		}
	}
	if canonical == nil || len(canonical.R) == 0 || len(canonical.S) == 0 {
		return nil, errors.New("no complete signature returned")
	}
	if !ecdsa.Verify(pub, job.digest, new(big.Int).SetBytes(canonical.R), new(big.Int).SetBytes(canonical.S)) {
		return nil, errors.New("threshold signature failed gateway verification")
	}
	completed = true
	return &SignResult{RequestID: job.job.ID, WalletID: job.request.WalletID, SiteID: job.request.SiteID, Index: job.request.Index, Path: derived.Path, Signature: "0x" + hex.EncodeToString(canonical.Signature), RecoveryID: hex.EncodeToString(canonical.Recovery), R: hex.EncodeToString(canonical.R), S: hex.EncodeToString(canonical.S)}, nil
}

func (g *Gateway) awaitNodeResponses(ctx context.Context, ch <-chan nodeResponse, requestID, sessionID, want string, nodes map[string]*gatewayNode) (map[string]*LinkFrame, error) {
	out := make(map[string]*LinkFrame, len(nodes))
	for len(out) < len(nodes) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case response := <-ch:
			frame := response.frame
			if frame == nil || frame.RequestID != requestID || frame.SessionID != sessionID {
				continue
			}
			if frame.Type == "ERROR" {
				return nil, fmt.Errorf("signer %s rejected request: %s", response.nodeID, frame.Error)
			}
			if frame.Type != want {
				continue
			}
			if _, duplicate := out[response.nodeID]; duplicate {
				continue
			}
			out[response.nodeID] = frame
		}
	}
	return out, nil
}

func (g *Gateway) sendAll(nodes map[string]*gatewayNode, makeFrame func(string) *LinkFrame) error {
	type sendResult struct{ err error }
	results := make(chan sendResult, len(nodes))
	for id, node := range nodes {
		go func(id string, node *gatewayNode) { results <- sendResult{node.sender.Send(makeFrame(id))} }(id, node)
	}
	for range nodes {
		if result := <-results; result.err != nil {
			return result.err
		}
	}
	return nil
}

func (g *Gateway) loadPublicWallet(walletID string) (derive.WalletMeta, error) {
	path := filepath.Join(g.cfg.WalletMetaDir, walletID, "wallet.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return derive.WalletMeta{}, fmt.Errorf("read public wallet metadata: %w", err)
	}
	var meta derive.WalletMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return derive.WalletMeta{}, err
	}
	if meta.WalletID != walletID || meta.Version != 1 {
		return derive.WalletMeta{}, errors.New("public wallet metadata ID/version mismatch")
	}
	return meta, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (g *Gateway) ServeHTTP(ctx context.Context) error {
	server := &http.Server{Addr: g.cfg.ListenHTTP, Handler: g.Authorized(g.HTTPHandler()), ReadHeaderTimeout: 5 * time.Second}
	if g.cfg.APICertificate != "" {
		cert, err := tls.LoadX509KeyPair(g.cfg.APICertificate, g.cfg.APIPrivateKey)
		if err != nil {
			return err
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	listener, err := net.Listen("tcp", g.cfg.ListenHTTP)
	if err != nil {
		return err
	}
	if server.TLSConfig == nil {
		err = server.Serve(listener)
	} else {
		err = server.ServeTLS(listener, "", "")
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
