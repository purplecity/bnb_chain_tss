package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const endpoint = "/v1/tss/message"

type HTTPSMesh struct {
	localParty string
	peerURLs   map[string]string
	clients    map[string]*http.Client
}

func NewHTTPSMesh(localParty string, certificate tls.Certificate, serverRoots *x509.CertPool, peerURLs, peerServerFingerprints map[string]string, timeout time.Duration) (*HTTPSMesh, error) {
	if localParty == "" || len(certificate.Certificate) == 0 || serverRoots == nil || len(peerURLs) < 1 || len(peerURLs) > 2 || len(peerServerFingerprints) != len(peerURLs) {
		return nil, errors.New("local identity, client certificate, roots, peer URLs and matching server certificate pins are required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	urls := make(map[string]string, len(peerURLs))
	clients := make(map[string]*http.Client, len(peerURLs))
	for id, value := range peerURLs {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("peer %q must have an HTTPS URL", id)
		}
		urls[id] = strings.TrimRight(value, "/")
		pin, ok := peerServerFingerprints[id]
		if !ok || len(pin) != 64 {
			return nil, fmt.Errorf("peer %q requires a SHA-256 server certificate fingerprint", id)
		}
		if _, err := hex.DecodeString(pin); err != nil {
			return nil, fmt.Errorf("peer %q fingerprint is not hex", id)
		}
		wantPin := strings.ToLower(pin)
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: serverRoots.Clone(), VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("peer server certificate is missing")
			}
			if CertificateFingerprint(state.PeerCertificates[0]) != wantPin {
				return errors.New("peer server certificate fingerprint mismatch")
			}
			return nil
		}}, MaxIdleConnsPerHost: 4}
		clients[id] = &http.Client{Timeout: timeout, Transport: transport}
	}
	if _, ok := urls[localParty]; ok {
		return nil, errors.New("peer URL map must contain remote members only")
	}
	return &HTTPSMesh{localParty: localParty, peerURLs: urls, clients: clients}, nil
}

func (m *HTTPSMesh) Send(ctx context.Context, recipient string, frame Frame) error {
	if frame.Sender != m.localParty || frame.Recipient != recipient {
		return errors.New("outbound frame identity mismatch")
	}
	peerURL, ok := m.peerURLs[recipient]
	if !ok {
		return errors.New("recipient is outside configured peer URLs")
	}
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peerURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.clients[recipient].Do(req)
	if err != nil {
		return fmt.Errorf("send authenticated protocol message: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("peer returned protocol transport status %d", resp.StatusCode)
	}
	return nil
}

type HTTPReceiver struct {
	serverCertificate  tls.Certificate
	clientCAs          *x509.CertPool
	peerCertificateIDs map[string]string
	mu                 sync.RWMutex
	sessions           map[string]*Session
}

func NewHTTPReceiver(serverCertificate tls.Certificate, clientCAs *x509.CertPool, peerCertificateIDs map[string]string) (*HTTPReceiver, error) {
	if len(serverCertificate.Certificate) == 0 || clientCAs == nil || len(peerCertificateIDs) != 3 {
		return nil, errors.New("server certificate, client CA and three pinned peer certificate identities are required")
	}
	return &HTTPReceiver{serverCertificate: serverCertificate, clientCAs: clientCAs, peerCertificateIDs: peerCertificateIDs, sessions: map[string]*Session{}}, nil
}

func (r *HTTPReceiver) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{r.serverCertificate}, ClientCAs: r.clientCAs, ClientAuth: tls.RequireAndVerifyClientCert}
}

func (r *HTTPReceiver) Register(session *Session) error {
	if session == nil {
		return errors.New("session is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[session.config.SessionID]; exists {
		return errors.New("session ID is already registered")
	}
	r.sessions[session.config.SessionID] = session
	return nil
}

func (r *HTTPReceiver) Unregister(sessionID string) {
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

func (r *HTTPReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != endpoint {
		http.NotFound(w, req)
		return
	}
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "mutual TLS peer certificate required", http.StatusUnauthorized)
		return
	}
	peerID, ok := r.peerCertificateIDs[CertificateFingerprint(req.TLS.PeerCertificates[0])]
	if !ok {
		http.Error(w, "unregistered peer certificate", http.StatusUnauthorized)
		return
	}
	var frame Frame
	decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		http.Error(w, "invalid protocol frame", http.StatusBadRequest)
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "trailing protocol frame data", http.StatusBadRequest)
		return
	}
	r.mu.RLock()
	session := r.sessions[frame.SessionID]
	r.mu.RUnlock()
	if session == nil {
		http.Error(w, "unknown protocol session", http.StatusNotFound)
		return
	}
	if err := session.Receive(req.Context(), peerID, frame); err != nil {
		http.Error(w, "protocol frame rejected", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func CertificateFingerprint(certificate *x509.Certificate) string {
	fingerprint := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(fingerprint[:])
}
