package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/v4/ecdsa/keygen"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	sign "github.com/purplecity/bnb_chain_tss/task2-sign"
	"github.com/purplecity/bnb_chain_tss/task3-address/derive"
	"github.com/tyler-smith/go-bip39"
)

const testMnemonic = "test test test test test test test test test test test junk"

func TestMultipleMnemonicWalletsSignConcurrentlyOverGRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two VSS wallet imports and concurrent three-node gRPC signing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	secrets := []*big.Int{scalarFromTestMnemonic(t, 0), scalarFromTestMnemonic(t, 1)}

	root := t.TempDir()
	generated := make([]struct {
		shares []keygen.LocalPartySaveData
		meta   derive.WalletMeta
	}, len(secrets))
	for i, secret := range secrets {
		var err error
		generated[i].shares, generated[i].meta, err = GenerateWalletShares(ctx, fmt.Sprintf("mnemonic-wallet-%d", i), secret)
		if err != nil {
			t.Fatalf("generate wallet %d: %v", i, err)
		}
		if err := WriteWalletFiles(filepath.Join(root, fmt.Sprintf("generated-%d", i)), generated[i].shares, generated[i].meta); err != nil {
			t.Fatal(err)
		}
	}
	for i := range generated {
		digest := sha256.Sum256([]byte(fmt.Sprintf("mnemonic wallet %d in-process control", i)))
		derived, tweak, err := derive.Derive(generated[i].meta, 23, uint32(100+i))
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := hex.DecodeString(derived.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := crypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := signDerivedInProcess(ctx, generated[i].shares, generated[i].meta, tweak, pub, digest[:]); err != nil {
			t.Fatalf("wallet %d in-process signature control failed: %v", i, err)
		}
	}

	nodeDirs := make(map[string]string, 3)
	metaDir := filepath.Join(root, "gateway-meta")
	for i := 1; i <= 3; i++ {
		nodeID := fmt.Sprintf("node-%d", i)
		nodeDirs[nodeID] = filepath.Join(root, nodeID)
		for j := range generated {
			walletID := generated[j].meta.WalletID
			source := filepath.Join(root, fmt.Sprintf("generated-%d", j), nodeID, walletID)
			if err := copyWalletDir(source, filepath.Join(nodeDirs[nodeID], walletID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range generated {
		walletID := generated[i].meta.WalletID
		source := filepath.Join(root, fmt.Sprintf("generated-%d", i), "public", walletID, "wallet.json")
		if err := copyFile(source, filepath.Join(metaDir, walletID, "wallet.json"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range generated {
		loaded := make([]keygen.LocalPartySaveData, 3)
		for nodeIndex := 1; nodeIndex <= 3; nodeIndex++ {
			wallet, err := sign.LoadWallet(nodeDirs[fmt.Sprintf("node-%d", nodeIndex)], generated[i].meta.WalletID, fmt.Sprintf("node-%d", nodeIndex))
			if err != nil {
				t.Fatalf("load persisted wallet %d on node-%d: %v", i, nodeIndex, err)
			}
			loaded[nodeIndex-1] = wallet.Share
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("mnemonic wallet %d persisted-data control", i)))
		derived, tweak, err := derive.Derive(generated[i].meta, 23, uint32(100+i))
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := hex.DecodeString(derived.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := crypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := signDerivedInProcess(ctx, loaded, generated[i].meta, tweak, pub, digest[:]); err != nil {
			t.Fatalf("wallet %d persisted-data signing control failed: %v", i, err)
		}
	}

	addresses := make(map[string]string, 3)
	for i := 1; i <= 3; i++ {
		address, err := reserveLocalAddress()
		if err != nil {
			t.Fatal(err)
		}
		addresses[fmt.Sprintf("node-%d", i)] = address
	}
	type serveResult struct {
		nodeID string
		err    error
	}
	serveErrors := make(chan serveResult, 3)
	for i := 1; i <= 3; i++ {
		nodeID := fmt.Sprintf("node-%d", i)
		peers := make(map[string]string, 2)
		for id, address := range addresses {
			if id != nodeID {
				peers[id] = address
			}
		}
		node, err := sign.NewNode(sign.NodeConfig{
			NodeID: nodeID, Listen: addresses[nodeID], WalletDir: nodeDirs[nodeID], Peers: peers,
		})
		if err != nil {
			t.Fatalf("create signer %s: %v", nodeID, err)
		}
		go func() { serveErrors <- serveResult{nodeID: nodeID, err: node.Serve(ctx)} }()
	}

	apiAddress, err := reserveLocalAddress()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := sign.NewGateway(sign.GatewayConfig{
		ListenHTTP: apiAddress, WalletMetaDir: metaDir, Nodes: addresses,
		APIKey: "integration-test-api-key", MaxConcurrent: 5, QueueSize: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Connect(ctx); err != nil {
		t.Fatalf("connect gateway to signer streams: %v", err)
	}
	apiErrors := make(chan error, 1)
	go func() { apiErrors <- gateway.ServeHTTP(ctx) }()
	client := &http.Client{Timeout: 5 * time.Second}
	apiURL := "http://" + apiAddress
	apiReady := false
	readyBy := time.Now().Add(5 * time.Second)
	for time.Now().Before(readyBy) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-API-Key", "integration-test-api-key")
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				apiReady = true
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !apiReady {
		t.Fatal("certificate-free gateway HTTP API did not become ready")
	}

	type submitted struct {
		jobID  string
		digest []byte
	}
	submittedJobs := make([]submitted, len(generated))
	postResults := make(chan error, len(generated))
	for i := range generated {
		digest := sha256.Sum256([]byte(fmt.Sprintf("mnemonic wallet %d signing integration", i)))
		body, err := json.Marshal(sign.SignRequest{WalletID: generated[i].meta.WalletID, SiteID: 23, Index: uint32(100 + i), Digest: hex.EncodeToString(digest[:])})
		if err != nil {
			t.Fatal(err)
		}
		go func(i int, body, digest []byte) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/v1/sign", bytes.NewReader(body))
			if err != nil {
				postResults <- err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", "integration-test-api-key")
			response, err := client.Do(req)
			if err != nil {
				postResults <- err
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusAccepted {
				postResults <- fmt.Errorf("wallet %d submit returned HTTP %d", i, response.StatusCode)
				return
			}
			var job sign.Job
			if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
				postResults <- err
				return
			}
			if job.ID == "" || job.Status != "queued" {
				postResults <- fmt.Errorf("unexpected submitted job: %#v", job)
				return
			}
			submittedJobs[i] = submitted{jobID: job.ID, digest: digest}
			postResults <- nil
		}(i, body, digest[:])
	}
	for range generated {
		if err := <-postResults; err != nil {
			t.Fatal(err)
		}
	}

	for i, submitted := range submittedJobs {
		job := waitForJob(t, ctx, client, apiURL, submitted.jobID)
		if job.Status != "succeeded" || job.Result == nil {
			t.Fatalf("wallet %d job failed: %#v", i, job)
		}
		if job.Result.WalletID != generated[i].meta.WalletID || job.Result.Path != fmt.Sprintf("m/23/%d", 100+i) {
			t.Fatalf("wallet %d returned incorrect result: %#v", i, job.Result)
		}
		derived, _, err := derive.Derive(generated[i].meta, 23, uint32(100+i))
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := hex.DecodeString(derived.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := crypto.UnmarshalPubkey(pubBytes)
		if err != nil {
			t.Fatal(err)
		}
		r, ok := new(big.Int).SetString(job.Result.R, 16)
		if !ok {
			t.Fatalf("wallet %d returned malformed r", i)
		}
		s, ok := new(big.Int).SetString(job.Result.S, 16)
		if !ok {
			t.Fatalf("wallet %d returned malformed s", i)
		}
		if !ecdsa.Verify(pub, submitted.digest, r, s) {
			t.Fatalf("wallet %d signature failed independent ECDSA verification", i)
		}
	}

	cancel()
	shutdownDeadline := time.NewTimer(10 * time.Second)
	defer shutdownDeadline.Stop()
	for range 3 {
		select {
		case result := <-serveErrors:
			if result.err != nil {
				t.Errorf("signer %s Serve returned: %v", result.nodeID, result.err)
			}
		case <-shutdownDeadline.C:
			t.Fatal("signer nodes did not stop within 10 seconds after cancellation")
		}
	}
	select {
	case err := <-apiErrors:
		if err != nil {
			t.Errorf("gateway ServeHTTP returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("gateway HTTP server did not stop after cancellation")
	}
}

func scalarFromTestMnemonic(t *testing.T, addressIndex uint32) *big.Int {
	t.Helper()
	// This published BIP-39 test phrase is only used to create disposable test wallets.
	mnemonic := "test test test test test test test test test test test junk"
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Fatal("embedded BIP-39 test phrase is invalid")
	}
	key, err := hdkeychain.NewMaster(bip39.NewSeed(mnemonic, ""), &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	path := []uint32{44 + hdkeychain.HardenedKeyStart, 60 + hdkeychain.HardenedKeyStart, hdkeychain.HardenedKeyStart, 0, addressIndex}
	for _, index := range path {
		key, err = key.Derive(index)
		if err != nil {
			t.Fatal(err)
		}
	}
	privateKey, err := key.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := crypto.ToECDSA(privateKey.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).Set(parsed.D)
}

func reserveLocalAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return address, nil
}

func copyWalletDir(source, target string) error {
	if err := os.MkdirAll(target, 0700); err != nil {
		return err
	}
	for _, name := range []string{"share.json", "wallet.json"} {
		if err := copyFile(filepath.Join(source, name), filepath.Join(target, name), 0600); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(source, target string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}

func waitForJob(t *testing.T, ctx context.Context, client *http.Client, apiURL, jobID string) sign.Job {
	t.Helper()
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/v1/jobs/"+jobID, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-API-Key", "integration-test-api-key")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var job sign.Job
		decodeErr := json.NewDecoder(response.Body).Decode(&job)
		response.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if job.Status == "succeeded" || job.Status == "failed" {
			return job
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-deadline.C:
			t.Fatalf("job %s did not finish before timeout", jobID)
		case <-poll.C:
		}
	}
}
