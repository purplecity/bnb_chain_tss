package sign

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type TLSFiles struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CA          string `json:"ca"`
}

func (f TLSFiles) configured() bool {
	return f.Certificate != "" || f.PrivateKey != "" || f.CA != ""
}

type NodeConfig struct {
	NodeID             string            `json:"node_id"`
	Listen             string            `json:"listen"`
	WalletDir          string            `json:"wallet_dir"`
	Peers              map[string]string `json:"peers"`
	TLS                TLSFiles          `json:"tls"`
	PeerFingerprints   map[string]string `json:"peer_fingerprints"`
	GatewayFingerprint string            `json:"gateway_fingerprint"`
}

type GatewayConfig struct {
	ListenHTTP       string            `json:"listen_http"`
	WalletMetaDir    string            `json:"wallet_meta_dir"`
	APICertificate   string            `json:"api_certificate"`
	APIPrivateKey    string            `json:"api_private_key"`
	Nodes            map[string]string `json:"nodes"`
	TLS              TLSFiles          `json:"tls"`
	NodeFingerprints map[string]string `json:"node_fingerprints"`
	APIKey           string            `json:"api_key"`
	MaxConcurrent    int               `json:"max_concurrent"`
	QueueSize        int               `json:"queue_size"`
}

func LoadJSON(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	return nil
}

func (f TLSFiles) serverConfig() (*tls.Config, error) {
	if f.Certificate == "" || f.PrivateKey == "" || f.CA == "" {
		return nil, errors.New("TLS requires certificate, private_key and ca")
	}
	cert, err := tls.LoadX509KeyPair(f.Certificate, f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(f.CA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA file contains no valid certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

func (f TLSFiles) clientConfig(expectedFingerprint string) (*tls.Config, error) {
	if f.Certificate == "" || f.PrivateKey == "" || f.CA == "" {
		return nil, errors.New("TLS requires certificate, private_key and ca")
	}
	cert, err := tls.LoadX509KeyPair(f.Certificate, f.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(f.CA)
	if err != nil {
		return nil, fmt.Errorf("read server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA file contains no valid certificates")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool}
	if expectedFingerprint != "" {
		want, err := normalizeFingerprint(expectedFingerprint)
		if err != nil {
			return nil, err
		}
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server did not present a certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("server certificate fingerprint does not match pin")
			}
			return nil
		}
	}
	return config, nil
}

func normalizeFingerprint(v string) (string, error) {
	v = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), ":", ""))
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("certificate fingerprint must be 32-byte SHA-256 hex")
	}
	return hex.EncodeToString(b), nil
}

func fingerprintFromTLS(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is missing")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}
