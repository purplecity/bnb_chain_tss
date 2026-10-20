package derive

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func testMeta() WalletMeta {
	priv, _ := crypto.GenerateKey()
	return WalletMeta{Version: 1, WalletID: "wallet-test", RootPub: hex.EncodeToString(crypto.CompressPubkey(&priv.PublicKey)), ChainCode: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
}

func TestDeriveDeterministicAndChainAddresses(t *testing.T) {
	meta := testMeta()
	a, _, err := Derive(meta, 9, 42)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Derive(meta, 9, 42)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("derivation is not deterministic: %#v != %#v", a, b)
	}
	if a.Path != "m/9/42" || len(a.EVM) != 42 || a.TRON == "" {
		t.Fatalf("unexpected derivation result: %#v", a)
	}
	other, _, err := Derive(meta, 9, 43)
	if err != nil {
		t.Fatal(err)
	}
	if other.PublicKey == a.PublicKey {
		t.Fatal("different index produced same child public key")
	}
	if err := ValidateAddressPair(meta, 9, 42, a.EVM, a.TRON); err != nil {
		t.Fatal(err)
	}
}

func TestDeriveRejectsHardenedIndexAndMalformedMetadata(t *testing.T) {
	meta := testMeta()
	if _, _, err := Derive(meta, HardenedStart, 1); err == nil {
		t.Fatal("hardened site index accepted")
	}
	meta.ChainCode = "00"
	if _, _, err := Derive(meta, 1, 1); err == nil {
		t.Fatal("malformed chain code accepted")
	}
}

func TestParsePrivateScalar(t *testing.T) {
	if _, err := ParsePrivateScalar("01"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParsePrivateScalar("0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("zero key accepted")
	}
	if _, err := ParsePrivateScalar("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"); err == nil {
		t.Fatal("scalar >= curve order accepted")
	}
	if _, err := ParsePrivateScalar("0000000000000000000000000000000000000000000000000000000000000001"); err != nil {
		t.Fatal(err)
	}
}
