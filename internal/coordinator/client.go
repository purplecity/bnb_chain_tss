// Package coordinator provides the control-plane client for coordinating
// independent signer HTTP handlers. It never receives a private share.
package coordinator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/purplecity/bnb_chain_tss/internal/policy"
	"github.com/purplecity/bnb_chain_tss/internal/signer"
	"github.com/purplecity/bnb_chain_tss/internal/transport"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
)

type Endpoint struct {
	ID                string
	URL               string
	ServerFingerprint string
}
type Config struct {
	Signers            []Endpoint
	ControlCertificate tls.Certificate
	ServerRoots        *x509.CertPool
	PollInterval       time.Duration
	RequestTimeout     time.Duration
}
type Client struct {
	signers     []Endpoint
	httpClients map[string]*http.Client
	poll        time.Duration
}

type DKGRequest struct {
	JobID     string `json:"job_id"`
	RequestID string `json:"request_id"`
	AttemptID string `json:"attempt_id"`
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	Epoch     uint64 `json:"epoch"`
}
type DKGResult struct {
	PublicKey   string `json:"public_key_uncompressed"`
	EVMAddress  string `json:"evm_address"`
	TRONAddress string `json:"tron_address"`
}
type SignRequest struct {
	JobID     string        `json:"job_id"`
	RequestID string        `json:"request_id"`
	AttemptID string        `json:"attempt_id"`
	SessionID string        `json:"session_id"`
	KeyID     string        `json:"key_id"`
	Epoch     uint64        `json:"epoch"`
	Selected  []string      `json:"selected"`
	Intent    policy.Intent `json:"intent"`
}
type Signature struct {
	R          string `json:"r"`
	S          string `json:"s"`
	RecoveryID byte   `json:"recovery_id"`
	Raw        string `json:"signature"`
}
type job struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Result []byte `json:"result"`
	Error  string `json:"error"`
}

func New(c Config) (*Client, error) {
	if len(c.Signers) != 3 || len(c.ControlCertificate.Certificate) == 0 || c.ServerRoots == nil {
		return nil, errors.New("three signers, control certificate and server roots are required")
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 250 * time.Millisecond
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second
	}
	signers := append([]Endpoint(nil), c.Signers...)
	sort.Slice(signers, func(i, j int) bool { return signers[i].ID < signers[j].ID })
	clients := make(map[string]*http.Client, 3)
	for i, peer := range signers {
		if peer.ID == "" || len(peer.ServerFingerprint) != 64 {
			return nil, errors.New("signer ID and SHA-256 server certificate fingerprint are required")
		}
		if i > 0 && signers[i-1].ID == peer.ID {
			return nil, errors.New("signer IDs must be unique")
		}
		if _, err := hex.DecodeString(peer.ServerFingerprint); err != nil {
			return nil, fmt.Errorf("signer %q fingerprint is not hex", peer.ID)
		}
		parsed, err := url.Parse(peer.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("signer %q must use an HTTPS URL", peer.ID)
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return nil, fmt.Errorf("signer %q URL must be an origin without a path", peer.ID)
		}
		signers[i].URL = strings.TrimRight(peer.URL, "/")
		pin := strings.ToLower(peer.ServerFingerprint)
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.ControlCertificate}, RootCAs: c.ServerRoots.Clone(), VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("signer server certificate is missing")
			}
			if transport.CertificateFingerprint(state.PeerCertificates[0]) != pin {
				return errors.New("signer server certificate pin mismatch")
			}
			return nil
		}}, MaxIdleConnsPerHost: 4}
		clients[peer.ID] = &http.Client{Timeout: c.RequestTimeout, Transport: transport}
	}
	return &Client{signers: signers, httpClients: clients, poll: c.PollInterval}, nil
}

func (c *Client) CreateKey(ctx context.Context, req DKGRequest) (DKGResult, error) {
	if req.JobID == "" || req.RequestID == "" || req.AttemptID == "" || req.SessionID == "" || req.KeyID == "" || req.Epoch == 0 {
		return DKGResult{}, errors.New("incomplete DKG request")
	}
	if err := c.forEach(ctx, func(ctx context.Context, s Endpoint) error { return c.post(ctx, s, "/v1/control/dkg/start", req, nil) }); err != nil {
		return DKGResult{}, err
	}
	results := make([]DKGResult, 0, 3)
	for _, s := range c.signers {
		var j job
		if err := c.waitJob(ctx, s, req.JobID, "READY", &j); err != nil {
			return DKGResult{}, err
		}
		var result DKGResult
		if err := json.Unmarshal(j.Result, &result); err != nil {
			return DKGResult{}, fmt.Errorf("decode DKG result from %s: %w", s.ID, err)
		}
		results = append(results, result)
	}
	for _, r := range results[1:] {
		if r != results[0] {
			return DKGResult{}, errors.New("signers produced different public keys or chain addresses")
		}
	}
	ready := make([]string, 0, 3)
	for _, s := range c.signers {
		ready = append(ready, s.ID)
	}
	hash, err := signer.ActivationManifestSHA256(req.KeyID, req.Epoch, results[0].PublicKey, ready)
	if err != nil {
		return DKGResult{}, err
	}
	activation := map[string]any{"job_id": req.JobID, "manifest_sha256": hex.EncodeToString(hash[:]), "public_key_uncompressed": results[0].PublicKey, "ready_parties": ready}
	if err := c.forEach(ctx, func(ctx context.Context, s Endpoint) error {
		return c.post(ctx, s, "/v1/control/keys/"+url.PathEscape(req.KeyID)+"/activate", activation, nil)
	}); err != nil {
		return DKGResult{}, fmt.Errorf("activation is partially applied or pending reconciliation: %w", err)
	}
	return results[0], nil
}

func (c *Client) Sign(ctx context.Context, req SignRequest) (Signature, error) {
	if req.JobID == "" || req.RequestID == "" || req.AttemptID == "" || req.SessionID == "" || req.KeyID == "" || req.Epoch == 0 || len(req.Selected) != 2 {
		return Signature{}, errors.New("incomplete 2-of-3 signing request")
	}
	if req.Intent.RequestID != req.RequestID || req.Intent.KeyID != req.KeyID || req.Intent.Epoch != req.Epoch {
		return Signature{}, errors.New("request identity differs from approved intent")
	}
	selected := map[string]bool{}
	for _, id := range req.Selected {
		selected[id] = true
	}
	if len(selected) != 2 {
		return Signature{}, errors.New("signing committee must contain two distinct signers")
	}
	var targets []Endpoint
	for _, s := range c.signers {
		if selected[s.ID] {
			targets = append(targets, s)
		}
	}
	if len(targets) != 2 {
		return Signature{}, errors.New("selected signer is outside configured committee")
	}
	for _, s := range targets {
		if err := c.post(ctx, s, "/v1/control/sign/start", req, nil); err != nil {
			return Signature{}, err
		}
	}
	var signatures []Signature
	for _, s := range targets {
		var j job
		if err := c.waitJob(ctx, s, req.JobID, "SIGNED", &j); err != nil {
			return Signature{}, err
		}
		var sig Signature
		if err := json.Unmarshal(j.Result, &sig); err != nil {
			return Signature{}, fmt.Errorf("decode signature from %s: %w", s.ID, err)
		}
		signatures = append(signatures, sig)
	}
	if signatures[0] != signatures[1] {
		return Signature{}, errors.New("selected signers returned inconsistent signature data")
	}
	return signatures[0], nil
}

func (c *Client) MarkBroadcast(ctx context.Context, jobID, txID string) error {
	return c.forSelected(ctx, jobID, func(ctx context.Context, s Endpoint) error {
		return c.post(ctx, s, "/v1/control/jobs/"+url.PathEscape(jobID)+"/broadcast", map[string]string{"tx_id": txID}, nil)
	})
}
func (c *Client) MarkComplete(ctx context.Context, jobID, txID string, block uint64, receipt string) error {
	return c.forSelected(ctx, jobID, func(ctx context.Context, s Endpoint) error {
		return c.post(ctx, s, "/v1/control/jobs/"+url.PathEscape(jobID)+"/complete", map[string]any{"tx_id": txID, "block_number": block, "receipt": receipt}, nil)
	})
}

func (c *Client) forSelected(ctx context.Context, jobID string, fn func(context.Context, Endpoint) error) error {
	var j job
	var targets []Endpoint
	for _, s := range c.signers {
		if err := c.get(ctx, s, "/v1/control/jobs/"+url.PathEscape(jobID), &j); err == nil && (j.Status == "SIGNED" || j.Status == "BROADCAST") {
			targets = append(targets, s)
		}
	}
	if len(targets) != 2 {
		return errors.New("could not identify the two signers for this job")
	}
	return c.forEndpoints(ctx, targets, fn)
}
func (c *Client) forEach(ctx context.Context, fn func(context.Context, Endpoint) error) error {
	return c.forEndpoints(ctx, c.signers, fn)
}
func (c *Client) forEndpoints(ctx context.Context, targets []Endpoint, fn func(context.Context, Endpoint) error) error {
	type failure struct {
		id  string
		err error
	}
	errs := make(chan failure, len(targets))
	var wg sync.WaitGroup
	for _, s := range targets {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx, s); err != nil {
				errs <- failure{s.ID, err}
			}
		}()
	}
	wg.Wait()
	close(errs)
	var out []string
	for failure := range errs {
		out = append(out, failure.id+": "+failure.err.Error())
	}
	if len(out) > 0 {
		sort.Strings(out)
		return errors.New(strings.Join(out, "; "))
	}
	return nil
}

func (c *Client) waitJob(ctx context.Context, s Endpoint, id, want string, out *job) error {
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	for {
		var current job
		err := c.get(ctx, s, "/v1/control/jobs/"+url.PathEscape(id), &current)
		if err == nil {
			if current.Status == want {
				*out = current
				return nil
			}
			switch current.Status {
			case "FAILED", "INTERRUPTED":
				return fmt.Errorf("signer %s job %s: %s %s", s.ID, id, current.Status, current.Error)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for signer %s job %s: %w", s.ID, id, ctx.Err())
		case <-ticker.C:
		}
	}
}
func (c *Client) post(ctx context.Context, s Endpoint, path string, value any, out any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(s, req, out, http.StatusAccepted, http.StatusOK)
}
func (c *Client) get(ctx context.Context, s Endpoint, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+path, nil)
	if err != nil {
		return err
	}
	return c.do(s, req, out, http.StatusOK)
}
func (c *Client) do(s Endpoint, req *http.Request, out any, accepted ...int) error {
	resp, err := c.httpClients[s.ID].Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ok := false
	for _, code := range accepted {
		if resp.StatusCode == code {
			ok = true
		}
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if readErr != nil {
		return readErr
	}
	if !ok {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("response has trailing JSON")
	}
	return nil
}

// DecodeSignature converts the API's fixed-width hexadecimal R/S values into
// raw scalars; chain-specific encoding remains in the chain adapter.
func DecodeSignature(sig Signature) (tssadapter.Signature, error) {
	rBytes, err := hex.DecodeString(sig.R)
	if err != nil {
		return tssadapter.Signature{}, err
	}
	sBytes, err := hex.DecodeString(sig.S)
	if err != nil {
		return tssadapter.Signature{}, err
	}
	raw, err := hex.DecodeString(sig.Raw)
	if err != nil {
		return tssadapter.Signature{}, err
	}
	if len(rBytes) == 0 || len(sBytes) == 0 || len(rBytes) > 32 || len(sBytes) > 32 || len(raw) != 64 || sig.RecoveryID > 1 {
		return tssadapter.Signature{}, errors.New("malformed threshold signature response")
	}
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)
	canonical := make([]byte, 64)
	r.FillBytes(canonical[:32])
	s.FillBytes(canonical[32:])
	if !bytes.Equal(raw, canonical) {
		return tssadapter.Signature{}, errors.New("signature scalars do not match raw signature")
	}
	return tssadapter.Signature{R: r, S: s, RecoveryID: sig.RecoveryID, Raw: raw}, nil
}
