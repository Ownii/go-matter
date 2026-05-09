package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestPBKDF2HmacSha256_KAT pins three published PBKDF2-HMAC-SHA256 vectors
// with password "password" and salt "salt", widely used as cross-language
// regression fixtures (see e.g. RFC 7914 §11 references and the cryptsetup
// project's test corpus).
func TestPBKDF2HmacSha256_KAT(t *testing.T) {
	cases := []struct {
		iters int
		want  string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, c := range cases {
		got := PBKDF2HmacSha256([]byte("password"), []byte("salt"), c.iters, 32)
		want, _ := hex.DecodeString(c.want)
		if !bytes.Equal(got, want) {
			t.Errorf("iters=%d: got %x, want %s", c.iters, got, c.want)
		}
	}
}

// TestSpake2pW0W1_Determinism — same inputs produce byte-identical outputs.
func TestSpake2pW0W1_Determinism(t *testing.T) {
	salt := []byte("SPAKE2P Key Salt")
	w0a, w1a, err := Spake2pW0W1FromPasscode(20202021, salt, 1000)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	w0b, w1b, err := Spake2pW0W1FromPasscode(20202021, salt, 1000)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(w0a, w0b) {
		t.Errorf("w0 not deterministic: %x vs %x", w0a, w0b)
	}
	if !bytes.Equal(w1a, w1b) {
		t.Errorf("w1 not deterministic: %x vs %x", w1a, w1b)
	}
}

// TestSpake2pW0W1_Vector regression-locks the bytes our derivation produces
// for the canonical Matter test passcode/salt/iteration triple. If a future
// change alters the wire output of SPAKE2+, this test fails and the change
// must be cross-checked against connectedhomeip's Spake2p/PASETest fixtures
// before being accepted.
func TestSpake2pW0W1_Vector(t *testing.T) {
	w0, w1, err := Spake2pW0W1FromPasscode(20202021, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		t.Fatalf("Spake2pW0W1FromPasscode: %v", err)
	}
	// Bytes locked against the current implementation. The algorithm matches
	// gomat (which interoperates with shipping Matter devices), but should be
	// cross-checked against connectedhomeip's PASETest fixtures during the
	// next interop pass.
	const (
		wantW0 = "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb35"
		wantW1 = "823d264225e36f4923b43ad64f8c862a30f4a129bbf9ee8074a32d6d67586a90"
	)
	if got := hex.EncodeToString(w0); got != wantW0 {
		t.Errorf("w0 mismatch:\n got  %s\n want %s", got, wantW0)
	}
	if got := hex.EncodeToString(w1); got != wantW1 {
		t.Errorf("w1 mismatch:\n got  %s\n want %s", got, wantW1)
	}
}

// TestComputeSPAKE2PVerifierData — L is a valid 65-byte uncompressed P-256
// point and is non-zero.
func TestComputeSPAKE2PVerifierData(t *testing.T) {
	w0, L, err := ComputeSPAKE2PVerifierData(20202021, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		t.Fatalf("ComputeSPAKE2PVerifierData: %v", err)
	}
	if len(w0) == 0 || len(w0) > 32 {
		t.Errorf("w0 length unexpected: %d", len(w0))
	}
	if len(L) != 65 {
		t.Fatalf("L length = %d, want 65", len(L))
	}
	if L[0] != 0x04 {
		t.Errorf("L not uncompressed (first byte = %#x, want 0x04)", L[0])
	}
}

// TestSpake2pW0W1_Errors — reject empty salt and non-positive iterations.
func TestSpake2pW0W1_Errors(t *testing.T) {
	if _, _, err := Spake2pW0W1FromPasscode(1, nil, 1000); err == nil {
		t.Error("expected error for empty salt")
	}
	if _, _, err := Spake2pW0W1FromPasscode(1, []byte("salt"), 0); err == nil {
		t.Error("expected error for zero iterations")
	}
}
