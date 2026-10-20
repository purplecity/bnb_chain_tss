package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSConfigRequiresMutualTLSAndPinsServerCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca-and-peer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "peer.pem"), filepath.Join(dir, "peer-key.pem"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	f := TLSFiles{Certificate: certPath, PrivateKey: keyPath, CA: caPath}
	server, err := f.serverConfig()
	if err != nil {
		t.Fatal(err)
	}
	if server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server TLS policy weakened: %#v", server)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(der)
	client, err := f.clientConfig(hex.EncodeToString(fingerprint[:]))
	if err != nil {
		t.Fatal(err)
	}
	if client.MinVersion != tls.VersionTLS13 || client.RootCAs == nil {
		t.Fatalf("client TLS config incomplete: %#v", client)
	}
	if err := client.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}); err != nil {
		t.Fatalf("pinned certificate rejected: %v", err)
	}
	wrong := sha256.Sum256([]byte("another certificate"))
	wrongClient, err := f.clientConfig(hex.EncodeToString(wrong[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongClient.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}); err == nil {
		t.Fatal("certificate with wrong pin accepted")
	}
}

func TestTLSConfigIsOptionalButMustBeCompleteWhenEnabled(t *testing.T) {
	if (TLSFiles{}).configured() {
		t.Fatal("empty TLS config should select certificate-free transport")
	}
	partial := TLSFiles{Certificate: "certificate.pem"}
	if !partial.configured() {
		t.Fatal("partial TLS config should be considered enabled")
	}
	if _, err := partial.serverConfig(); err == nil {
		t.Fatal("partial server TLS config accepted")
	}
	if _, err := partial.clientConfig(""); err == nil {
		t.Fatal("partial client TLS config accepted")
	}
}
