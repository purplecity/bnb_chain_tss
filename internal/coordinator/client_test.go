package coordinator

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestDecodeSignatureValidatesRawScalars(t *testing.T) {
	raw := make([]byte, 64)
	raw[31] = 1
	raw[63] = 2
	sig := Signature{R: "01", S: "02", RecoveryID: 1, Raw: hex.EncodeToString(raw)}
	decoded, err := DecodeSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.R.Cmp(big.NewInt(1)) != 0 || decoded.S.Cmp(big.NewInt(2)) != 0 || decoded.RecoveryID != 1 || len(decoded.Raw) != 64 {
		t.Fatalf("unexpected decoded signature: R=%s S=%s recovery=%d raw-len=%d", decoded.R, decoded.S, decoded.RecoveryID, len(decoded.Raw))
	}
	sig.Raw = hex.EncodeToString(make([]byte, 64))
	if _, err := DecodeSignature(sig); err == nil {
		t.Fatal("accepted raw signature inconsistent with R/S")
	}
}
