package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDeriveSessionKeysFromKe_Slicing verifies that the three returned keys
// are exactly the three 16-byte windows of one 48-byte HKDF expansion under
// the documented (salt, info) parameters. Independent of any locked vector:
// if HKDF itself is correct (covered by hkdf_test.go), this test certifies
// the windowing logic.
func TestDeriveSessionKeysFromKe_Slicing(t *testing.T) {
	ke := bytes.Repeat([]byte{0x42}, 16)

	full, err := HKDF(ke, nil, []byte(SessionKeyInfo), 48)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}

	keys, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("DeriveSessionKeysFromKe: %v", err)
	}
	if !bytes.Equal(keys.I2RKey, full[0:16]) {
		t.Errorf("I2RKey mismatch\ngot:  %x\nwant: %x", keys.I2RKey, full[0:16])
	}
	if !bytes.Equal(keys.R2IKey, full[16:32]) {
		t.Errorf("R2IKey mismatch\ngot:  %x\nwant: %x", keys.R2IKey, full[16:32])
	}
	if !bytes.Equal(keys.AttestationChallenge, full[32:48]) {
		t.Errorf("AttestationChallenge mismatch\ngot:  %x\nwant: %x",
			keys.AttestationChallenge, full[32:48])
	}
}

// TestDeriveSessionKeysFromKe_LockedVector is a regression lock against a
// hand-captured output for Ke = 0x42 × 16. It guards against any silent
// change to the HKDF parameters (salt, info, length, ordering).
//
// This is a *regression* vector, not a spec-verified one — see the TODO in
// session_keys.go about cross-checking against connectedhomeip.
func TestDeriveSessionKeysFromKe_LockedVector(t *testing.T) {
	ke := bytes.Repeat([]byte{0x42}, 16)

	wantI2R, _ := hex.DecodeString("2f65c7d3e256ff8f55c447d519d2fe59")
	wantR2I, _ := hex.DecodeString("3c4b754dcc7d8287c18d2cf5e9d77fcb")
	wantAC, _ := hex.DecodeString("e8aa05b7a16076bf022c1eadac021819")

	keys, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("DeriveSessionKeysFromKe: %v", err)
	}
	if !bytes.Equal(keys.I2RKey, wantI2R) {
		t.Errorf("I2RKey regression\ngot:  %x\nwant: %x", keys.I2RKey, wantI2R)
	}
	if !bytes.Equal(keys.R2IKey, wantR2I) {
		t.Errorf("R2IKey regression\ngot:  %x\nwant: %x", keys.R2IKey, wantR2I)
	}
	if !bytes.Equal(keys.AttestationChallenge, wantAC) {
		t.Errorf("AttestationChallenge regression\ngot:  %x\nwant: %x",
			keys.AttestationChallenge, wantAC)
	}
}

func TestDeriveSessionKeysFromKe_Deterministic(t *testing.T) {
	ke := bytes.Repeat([]byte{0x37}, 16)
	a, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !bytes.Equal(a.I2RKey, b.I2RKey) ||
		!bytes.Equal(a.R2IKey, b.R2IKey) ||
		!bytes.Equal(a.AttestationChallenge, b.AttestationChallenge) {
		t.Error("DeriveSessionKeysFromKe is not deterministic")
	}
}

// TestDeriveSessionKeysFromKe_KeysAreDistinct catches a slicing bug where
// two of the three windows would alias or overlap.
func TestDeriveSessionKeysFromKe_KeysAreDistinct(t *testing.T) {
	ke := bytes.Repeat([]byte{0x99}, 16)
	keys, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.I2RKey, keys.R2IKey) {
		t.Error("I2RKey == R2IKey")
	}
	if bytes.Equal(keys.I2RKey, keys.AttestationChallenge) {
		t.Error("I2RKey == AttestationChallenge")
	}
	if bytes.Equal(keys.R2IKey, keys.AttestationChallenge) {
		t.Error("R2IKey == AttestationChallenge")
	}
	if len(keys.I2RKey) != 16 ||
		len(keys.R2IKey) != 16 ||
		len(keys.AttestationChallenge) != 16 {
		t.Errorf("unexpected key lengths: %d/%d/%d",
			len(keys.I2RKey), len(keys.R2IKey), len(keys.AttestationChallenge))
	}
}

// TestDeriveSessionKeysFromKe_AESRoundTrip seals plaintext with I2RKey and
// confirms a fresh derivation of the same Ke produces a key that opens it.
// This is the end-to-end shape commissioning will rely on: derive once on
// the initiator, derive again on the responder, AES-CCM round-trips.
func TestDeriveSessionKeysFromKe_AESRoundTrip(t *testing.T) {
	ke := bytes.Repeat([]byte{0xa5}, 16)
	initiator, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatal(err)
	}

	provider := &DefaultCryptoProvider{}
	nonce := BuildNonce(0, 1, 0xdeadbeefcafebabe)
	plaintext := []byte("matter PASE secured frame")
	aad := []byte("message header")

	ct, err := provider.Encrypt(initiator.I2RKey, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := provider.Decrypt(responder.I2RKey, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("round-trip mismatch\ngot:  %s\nwant: %s", pt, plaintext)
	}
}

func TestDeriveSessionKeysFromKe_EmptyKe(t *testing.T) {
	if _, err := DeriveSessionKeysFromKe(nil); err == nil {
		t.Error("expected error for nil Ke, got nil")
	}
	if _, err := DeriveSessionKeysFromKe([]byte{}); err == nil {
		t.Error("expected error for empty Ke, got nil")
	}
}
