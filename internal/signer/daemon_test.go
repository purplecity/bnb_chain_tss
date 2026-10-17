package signer

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActivationManifestHashNormalizesPartyOrder(t *testing.T) {
	a, err := ActivationManifestSHA256("wallet", 2, "04abcdef", []string{"c", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ActivationManifestSHA256("wallet", 2, "04abcdef", []string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("party ordering changed canonical activation hash")
	}
	if _, err := ActivationManifestSHA256("wallet", 2, "04abcdef", []string{"a", "a", "c"}); err == nil {
		t.Fatal("duplicate party accepted")
	}
}

func TestControlAPIRequiresPinnedMutualTLSCertificate(t *testing.T) {
	raw := []byte("test-control-certificate")
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	d := &Daemon{c: Config{ControlCertificateIDs: map[string]struct{}{pin: {}}}}
	req := httptest.NewRequest(http.MethodGet, "/v1/control/health", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: raw}}}
	response := httptest.NewRecorder()
	d.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("pinned control certificate rejected: %d %s", response.Code, response.Body.String())
	}
	bad := httptest.NewRequest(http.MethodGet, "/v1/control/health", nil)
	bad.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("other")}}}
	response = httptest.NewRecorder()
	d.ServeHTTP(response, bad)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unregistered control certificate accepted: %d", response.Code)
	}
}

func TestControlDecoderRejectsTrailingGarbage(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ok":true}garbage`))
	response := httptest.NewRecorder()
	var value struct {
		OK bool `json:"ok"`
	}
	if decode(response, req, &value) {
		t.Fatal("decoder accepted trailing bytes")
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d", response.Code)
	}
}
