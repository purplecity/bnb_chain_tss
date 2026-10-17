// Package signer exposes a small mTLS control API around one isolated TSS
// participant. The coordinator never receives or reconstructs local shares.
package signer

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/purplecity/bnb_chain_tss/internal/chain/evm"
	"github.com/purplecity/bnb_chain_tss/internal/policy"
	"github.com/purplecity/bnb_chain_tss/internal/sharestore"
	"github.com/purplecity/bnb_chain_tss/internal/transport"
	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
	"github.com/purplecity/bnb_chain_tss/internal/workflow"
)

type ShareStore interface {
	Put(context.Context, sharestore.Record) error
	Get(context.Context, sharestore.Identity) (sharestore.Record, error)
}

// IntentValidator must decode the full chain transaction and independently
// verify policy/approval evidence on each signer, then return its exact digest.
type IntentValidator interface {
	Validate(policy.Intent) ([]byte, error)
}
type IntentValidatorFunc func(policy.Intent) ([]byte, error)

func (f IntentValidatorFunc) Validate(i policy.Intent) ([]byte, error) { return f(i) }

type Config struct {
	LocalParty            string
	Members               []tssadapter.Participant
	ControlCertificateIDs map[string]struct{}
	Mesh                  transport.Mesh
	Receiver              *transport.HTTPReceiver
	Store                 ShareStore
	OnlineWrapper         sharestore.KeyWrapper
	RecoveryWrapper       sharestore.KeyWrapper
	Journal               *workflow.Journal
	Validator             IntentValidator
}

type Daemon struct {
	c      Config
	mu     sync.Mutex
	active map[string]string
}

func New(c Config) (*Daemon, error) {
	if c.LocalParty == "" || len(c.Members) != tssadapter.CommitteeSize || c.Mesh == nil || c.Receiver == nil || c.Store == nil || c.OnlineWrapper == nil || c.RecoveryWrapper == nil || c.Journal == nil || len(c.ControlCertificateIDs) == 0 {
		return nil, errors.New("incomplete signer daemon configuration")
	}
	found := false
	for _, member := range c.Members {
		if member.ID == c.LocalParty {
			found = true
		}
	}
	if !found {
		return nil, errors.New("local signer is outside committee")
	}
	return &Daemon{c: c, active: map[string]string{}}, nil
}

type dkgRequest struct {
	JobID     string `json:"job_id"`
	RequestID string `json:"request_id"`
	AttemptID string `json:"attempt_id"`
	SessionID string `json:"session_id"`
	KeyID     string `json:"key_id"`
	Epoch     uint64 `json:"epoch"`
}
type signRequest struct {
	JobID     string        `json:"job_id"`
	RequestID string        `json:"request_id"`
	AttemptID string        `json:"attempt_id"`
	SessionID string        `json:"session_id"`
	KeyID     string        `json:"key_id"`
	Epoch     uint64        `json:"epoch"`
	Selected  []string      `json:"selected"`
	Intent    policy.Intent `json:"intent"`
}
type activateRequest struct {
	JobID          string   `json:"job_id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	PublicKey      string   `json:"public_key_uncompressed"`
	ReadyParties   []string `json:"ready_parties"`
}
type dkgResult struct {
	PublicKey        string `json:"public_key_uncompressed"`
	EVMLegacyAddress string `json:"evm_address"`
	TRONAddress      string `json:"tron_address"`
}
type signatureResult struct {
	R          string `json:"r"`
	S          string `json:"s"`
	RecoveryID byte   `json:"recovery_id"`
	Raw        string `json:"signature"`
}

func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/tss/message" {
		d.c.Receiver.ServeHTTP(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
		return
	}
	fingerprint := transport.CertificateFingerprint(r.TLS.PeerCertificates[0])
	if _, ok := d.c.ControlCertificateIDs[fingerprint]; !ok {
		http.Error(w, "unauthorized control certificate", http.StatusForbidden)
		return
	}
	switch {
	case r.URL.Path == "/v1/control/health" && r.Method == http.MethodGet:
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/v1/control/dkg/start" && r.Method == http.MethodPost:
		d.startDKG(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/control/jobs/") && r.Method == http.MethodGet:
		d.getJob(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/control/keys/") && strings.HasSuffix(r.URL.Path, "/activate") && r.Method == http.MethodPost:
		d.activate(w, r)
	case r.URL.Path == "/v1/control/sign/start" && r.Method == http.MethodPost:
		d.startSign(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/control/jobs/") && strings.HasSuffix(r.URL.Path, "/broadcast") && r.Method == http.MethodPost:
		d.broadcast(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/control/jobs/") && strings.HasSuffix(r.URL.Path, "/complete") && r.Method == http.MethodPost:
		d.complete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (d *Daemon) startDKG(w http.ResponseWriter, r *http.Request) {
	var req dkgRequest
	if !decode(w, r, &req) {
		return
	}
	if req.JobID == "" || req.KeyID == "" || req.Epoch == 0 {
		http.Error(w, "job_id, key_id and epoch are required", 400)
		return
	}
	floor, err := d.c.Journal.MinimumEpoch(req.KeyID)
	if err != nil {
		http.Error(w, "journal failure", 500)
		return
	}
	if req.Epoch <= floor {
		http.Error(w, "epoch must exceed the committed key epoch", 409)
		return
	}
	job, err := d.c.Journal.Begin(workflow.Job{ID: req.JobID, Kind: "DKG", RequestID: req.RequestID, KeyID: req.KeyID, Epoch: req.Epoch, AttemptID: req.AttemptID, SessionID: req.SessionID})
	if err != nil {
		http.Error(w, "workflow conflict or incomplete attempt identity", 409)
		return
	}
	job, err = d.c.Journal.Transition(job.ID, job.Version, workflow.Running, nil, nil)
	if err != nil {
		http.Error(w, "could not durably start DKG", 409)
		return
	}
	meta := tssadapter.SessionMeta{SessionID: req.SessionID, AttemptID: req.AttemptID, KeyID: req.KeyID, Epoch: req.Epoch}
	session, err := tssadapter.NewDistributedDKG(meta, d.c.LocalParty, d.c.Members, d.c.Mesh)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "could not create DKG session", 400)
		return
	}
	if err = d.c.Receiver.Register(session.TransportSession()); err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "could not register DKG session", 409)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": job.ID, "status": job.Status})
	go d.runDKG(job, session)
}

func (d *Daemon) runDKG(job workflow.Job, session *tssadapter.ProtocolSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	defer d.c.Receiver.Unregister(job.SessionID)
	value, err := session.Run(ctx)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		return
	}
	save, ok := value.(*keygen.LocalPartySaveData)
	if !ok || save == nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, errors.New("DKG result type invalid"))
		return
	}
	identity := sharestore.Identity{KeyID: job.KeyID, Epoch: job.Epoch, Party: d.c.LocalParty, Schema: sharestore.SchemaVersion}
	record, err := sharestore.Protect(ctx, *save, identity, d.c.OnlineWrapper, d.c.RecoveryWrapper)
	if err == nil {
		err = d.c.Store.Put(ctx, record)
	}
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		return
	}
	public := save.ECDSAPub.ToECDSAPubKey()
	// tss-lib uses secp256k1. Use its public-key coordinates directly and
	// derive both chain address forms from the same validated point.
	pub := &ecdsa.PublicKey{Curve: public.Curve, X: public.X, Y: public.Y}
	pubBytes := make([]byte, 65)
	pubBytes[0] = 4
	public.X.FillBytes(pubBytes[1:33])
	public.Y.FillBytes(pubBytes[33:])
	evmAddress := evm.AddressFromPublicKey(pub)
	tronAddress := append([]byte{0x41}, evmAddress.Bytes()...)
	result := dkgResult{PublicKey: hex.EncodeToString(pubBytes), EVMLegacyAddress: evmAddress.Hex(), TRONAddress: hex.EncodeToString(tronAddress)}
	encoded, _ := json.Marshal(result)
	_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Ready, encoded, nil)
}

func (d *Daemon) activate(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/control/keys/"), "/activate")
	var req activateRequest
	if !decode(w, r, &req) {
		return
	}
	if keyID == "" || req.JobID == "" {
		http.Error(w, "key and job IDs are required", 400)
		return
	}
	job, err := d.c.Journal.Get(req.JobID)
	if err != nil || job.KeyID != keyID || job.Kind != "DKG" || job.Status != workflow.Ready {
		http.Error(w, "DKG job is not ready for activation", 409)
		return
	}
	var local dkgResult
	if err := json.Unmarshal(job.Result, &local); err != nil || req.PublicKey == "" || req.PublicKey != local.PublicKey {
		http.Error(w, "activation public key does not match this signer DKG result", 409)
		return
	}
	wantParties := make([]string, 0, len(d.c.Members))
	for _, member := range d.c.Members {
		wantParties = append(wantParties, member.ID)
	}
	gotParties := append([]string(nil), req.ReadyParties...)
	sort.Strings(wantParties)
	sort.Strings(gotParties)
	if len(gotParties) != len(wantParties) {
		http.Error(w, "activation must name every ready signer", 409)
		return
	}
	for i := range wantParties {
		if gotParties[i] != wantParties[i] {
			http.Error(w, "activation signer set differs from configured committee", 409)
			return
		}
	}
	manifest, err := hex.DecodeString(req.ManifestSHA256)
	if err != nil || len(manifest) != 32 {
		http.Error(w, "manifest_sha256 must be 32-byte hex", 400)
		return
	}
	actualManifest, err := ActivationManifestSHA256(keyID, job.Epoch, req.PublicKey, wantParties)
	if err != nil || !equalDigest(manifest, actualManifest[:]) {
		http.Error(w, "activation manifest hash does not match its contents", 409)
		return
	}
	if err = d.c.Journal.DecideEpochCommit(keyID, job.Epoch, manifest); err != nil {
		http.Error(w, "epoch commit conflict", 409)
		return
	}
	job, err = d.c.Journal.Transition(job.ID, job.Version, workflow.Active, nil, nil)
	if err != nil {
		http.Error(w, "epoch committed but activation status requires retry/reconciliation", 409)
		return
	}
	d.mu.Lock()
	d.active[keyID] = job.ID
	d.mu.Unlock()
	writeJSON(w, 200, job)
}

func (d *Daemon) startSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if !decode(w, r, &req) {
		return
	}
	if d.c.Validator == nil {
		http.Error(w, "signing policy is not configured", 503)
		return
	}
	active, err := d.c.Journal.CanSign(req.KeyID, req.Epoch)
	if err != nil || !active {
		http.Error(w, "requested key epoch is not the current active epoch", 409)
		return
	}
	if req.Intent.KeyID != req.KeyID || req.Intent.Epoch != req.Epoch || req.Intent.RequestID != req.RequestID {
		http.Error(w, "signing request differs from approved intent", 400)
		return
	}
	digest, err := d.c.Validator.Validate(req.Intent)
	if err != nil {
		http.Error(w, "transaction or approval policy rejected", 403)
		return
	}
	if len(digest) != 32 {
		http.Error(w, "chain validator returned invalid digest", 500)
		return
	}
	selected := make([]tssadapter.Participant, 0, len(req.Selected))
	for _, id := range req.Selected {
		for _, member := range d.c.Members {
			if member.ID == id {
				selected = append(selected, member)
			}
		}
	}
	if len(selected) != tssadapter.MinSigners {
		http.Error(w, "exactly two configured signers must be selected", 400)
		return
	}
	job, err := d.c.Journal.Begin(workflow.Job{ID: req.JobID, Kind: "SIGN", RequestID: req.RequestID, KeyID: req.KeyID, Epoch: req.Epoch, AttemptID: req.AttemptID, SessionID: req.SessionID, Digest: digest})
	if err != nil {
		http.Error(w, "workflow conflict or incomplete attempt identity", 409)
		return
	}
	job, err = d.c.Journal.Transition(job.ID, job.Version, workflow.Running, nil, nil)
	if err != nil {
		http.Error(w, "could not durably start signing", 409)
		return
	}
	identity := sharestore.Identity{KeyID: req.KeyID, Epoch: req.Epoch, Party: d.c.LocalParty, Schema: sharestore.SchemaVersion}
	record, err := d.c.Store.Get(r.Context(), identity)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "local share is unavailable", 503)
		return
	}
	save, err := sharestore.RestoreOnline(r.Context(), record, d.c.OnlineWrapper)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "local share cannot be decrypted", 503)
		return
	}
	meta := tssadapter.SessionMeta{SessionID: req.SessionID, AttemptID: req.AttemptID, KeyID: req.KeyID, Epoch: req.Epoch}
	session, err := tssadapter.NewDistributedSign(meta, d.c.LocalParty, d.c.Members, selected, save, digest, d.c.Mesh)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "could not create signing session", 400)
		return
	}
	if err = d.c.Receiver.Register(session.TransportSession()); err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		http.Error(w, "could not register signing session", 409)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": job.ID, "status": job.Status})
	go d.runSign(job, session)
}

func (d *Daemon) runSign(job workflow.Job, session *tssadapter.ProtocolSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	defer d.c.Receiver.Unregister(job.SessionID)
	value, err := session.Run(ctx)
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		return
	}
	sig, ok := value.(*common.SignatureData)
	if !ok || sig == nil || len(sig.R) == 0 || len(sig.S) == 0 || len(sig.SignatureRecovery) == 0 {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, errors.New("signing result is empty"))
		return
	}
	encoded, err := json.Marshal(signatureResult{R: hex.EncodeToString(sig.R), S: hex.EncodeToString(sig.S), RecoveryID: sig.SignatureRecovery[0], Raw: hex.EncodeToString(sig.Signature)})
	if err != nil {
		_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Failed, nil, err)
		return
	}
	_, _ = d.c.Journal.Transition(job.ID, job.Version, workflow.Signed, encoded, nil)
}

func (d *Daemon) getJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/control/jobs/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}
	job, err := d.c.Journal.Get(id)
	if err != nil {
		http.Error(w, "job not found", 404)
		return
	}
	writeJSON(w, 200, job)
}
func (d *Daemon) broadcast(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "invalid job path", 400)
		return
	}
	job, err := d.c.Journal.Get(parts[3])
	if err != nil || job.Status != workflow.Signed && job.Status != workflow.Broadcast {
		http.Error(w, "job is not signed", 409)
		return
	}
	var req struct {
		TxID string `json:"tx_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.TxID == "" {
		http.Error(w, "tx_id required", 400)
		return
	}
	if job.Status == workflow.Signed {
		job, err = d.c.Journal.Transition(job.ID, job.Version, workflow.Broadcast, []byte(req.TxID), nil)
	} else if string(job.Result) != req.TxID {
		http.Error(w, "job already records a different broadcast transaction ID", 409)
		return
	}
	if err != nil {
		http.Error(w, "could not persist broadcast result", 409)
		return
	}
	writeJSON(w, 200, job)
}

func (d *Daemon) complete(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 {
		http.Error(w, "invalid job path", 400)
		return
	}
	job, err := d.c.Journal.Get(parts[3])
	if err != nil || job.Status != workflow.Broadcast {
		http.Error(w, "job is not awaiting chain confirmation", 409)
		return
	}
	var req struct {
		TxID        string `json:"tx_id"`
		BlockNumber uint64 `json:"block_number"`
		Receipt     string `json:"receipt"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.TxID == "" || req.BlockNumber == 0 || req.Receipt == "" {
		http.Error(w, "tx_id, block_number and verified receipt are required", 400)
		return
	}
	var broadcastID string
	if err := json.Unmarshal(job.Result, &broadcastID); err != nil || broadcastID != req.TxID {
		http.Error(w, "confirmation transaction ID differs from recorded broadcast", 409)
		return
	}
	result, _ := json.Marshal(req)
	job, err = d.c.Journal.Transition(job.ID, job.Version, workflow.Complete, result, nil)
	if err != nil {
		http.Error(w, "could not persist completion", 409)
		return
	}
	writeJSON(w, 200, job)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid request body", 400)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "trailing request data", 400)
		return false
	}
	return true
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
