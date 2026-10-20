package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	keyFile := flag.String("private-key", "private_key.txt", "offline plaintext private key file (64 hex chars, no 0x prefix)")
	walletID := flag.String("wallet-id", "", "wallet identifier")
	outDir := flag.String("out-dir", "", "new output directory, must not already exist")
	flag.Parse()
	if *walletID == "" || *outDir == "" {
		fatal("--wallet-id and --out-dir are required")
	}
	secret, err := readPrivateKeyFile(*keyFile)
	if err != nil {
		fatal("read/validate private key: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dkgTimeout+time.Minute)
	defer cancel()
	shares, meta, err := GenerateWalletShares(ctx, *walletID, secret)
	secret.SetInt64(0)
	if err != nil {
		fatal("generate wallet shares: %v", err)
	}
	if err := WriteWalletFiles(*outDir, shares, meta); err != nil {
		fatal("write wallet shares: %v", err)
	}
	fmt.Printf("generated three signer folders under %s\n", *outDir)
	fmt.Println("treat each share.json as a private key: keep it on its assigned signer and use an encrypted transfer channel")
}

func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
