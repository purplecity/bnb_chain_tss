package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPSMeshMutualTLSReliableBroadcast(t *testing.T) {
	root, rootKey, rootCert := newTestCA(t)
	members := []string{"a", "b", "c"}
	certificates := map[string]tls.Certificate{}
	fingerprints := map[string]string{}
	for _, id := range members {
		cert := newTestPeerCertificate(t, rootKey, rootCert, id)
		certificates[id] = cert
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		fingerprints[CertificateFingerprint(parsed)] = id
	}
	receivers := map[string]*HTTPReceiver{}
	servers := map[string]*httptest.Server{}
	for _, id := range members {
		receiver, err := NewHTTPReceiver(certificates[id], root, fingerprints)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(receiver)
		server.TLS = receiver.TLSConfig()
		server.StartTLS()
		t.Cleanup(server.Close)
		receivers[id] = receiver
		servers[id] = server
	}
	urls := map[string]string{}
	for id, server := range servers {
		urls[id] = server.URL
	}
	meshes := map[string]*HTTPSMesh{}
	for _, id := range members {
		peers := map[string]string{}
		pins := map[string]string{}
		for other, url := range urls {
			if other != id {
				peers[other] = url
				certificate, err := x509.ParseCertificate(certificates[other].Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				pins[other] = CertificateFingerprint(certificate)
			}
		}
		mesh, err := NewHTTPSMesh(id, certificates[id], root, peers, pins, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		meshes[id] = mesh
	}
	wrongPins := map[string]string{"b": strings.Repeat("0", 64)}
	wrongMesh, err := NewHTTPSMesh("a", certificates["a"], root, map[string]string{"b": urls["b"]}, wrongPins, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := wrongMesh.Send(context.Background(), "b", Frame{SessionID: "pin-check", AttemptID: "a", KeyID: "k", Epoch: 1, Kind: KindDirect, Sender: "a", Recipient: "b", Sequence: 1, Payload: []byte("x")}); err == nil {
		t.Fatal("mesh accepted a CA-valid server with the wrong pinned certificate")
	}
	delivered := map[string][]string{}
	sessions := map[string]*Session{}
	for _, id := range members {
		id := id
		session, err := NewSession(SessionConfig{SessionID: "http-session", AttemptID: "http-attempt", KeyID: "http-key", Epoch: 1, LocalParty: id, Members: members}, meshes[id], func(_ context.Context, from string, payload []byte, broadcast bool) error {
			kind := "direct"
			if broadcast {
				kind = "broadcast"
			}
			delivered[id] = append(delivered[id], kind+":"+from+":"+string(payload))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions[id] = session
		if err := receivers[id].Register(session); err != nil {
			t.Fatal(err)
		}
	}
	if err := sessions["a"].Broadcast(context.Background(), []byte("authenticated and echoed")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"b", "c"} {
		if len(delivered[id]) != 1 || delivered[id][0] != "broadcast:a:authenticated and echoed" {
			t.Fatalf("party %s got %v", id, delivered[id])
		}
	}
	if err := sessions["a"].SendDirect(context.Background(), "c", []byte("private peer message")); err != nil {
		t.Fatal(err)
	}
	if len(delivered["b"]) != 1 || len(delivered["c"]) != 2 || delivered["c"][1] != "direct:a:private peer message" {
		t.Fatalf("unexpected authenticated deliveries: %v", delivered)
	}
}

func newTestCA(t *testing.T) (*x509.CertPool, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, key, cert
}

func newTestPeerCertificate(t *testing.T, caKey *rsa.PrivateKey, issuer *x509.Certificate, id string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
