// Command tss-demo runs the complete 2-of-3 protocol inside one local process.
// It is an educational smoke demo; it is not a deployed wallet or signer.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/purplecity/bnb_chain_tss/internal/tssadapter"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	keys, err := tssadapter.GenerateKeySet(ctx)
	if err != nil {
		log.Fatal(err)
	}
	publicKey := append(keys.PublicKey.X.FillBytes(make([]byte, 32)), keys.PublicKey.Y.FillBytes(make([]byte, 32))...)
	fmt.Printf("Development-only local 2-of-3 MPC demo\n")
	fmt.Printf("BNB tss-lib: v2.0.2\n")
	fmt.Printf("Public key (uncompressed coordinates): 0x%s\n", hex.EncodeToString(publicKey))
	fmt.Printf("Private shares: %d (held in memory only)\n", len(keys.Shares))
	digest := sha256.Sum256([]byte("local demo transaction intent; not a blockchain transaction"))
	fmt.Printf("Synthetic digest: 0x%s\n", hex.EncodeToString(digest[:]))
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		sig, err := tssadapter.SignPair(ctx, keys, pair, digest[:])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s + %s signature verified: r=0x%x s=0x%x recovery_id=%d\n", keys.PartyIDs[pair[0]], keys.PartyIDs[pair[1]], sig.R, sig.S, sig.RecoveryID)
	}
}
