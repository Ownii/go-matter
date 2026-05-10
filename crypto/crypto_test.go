package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

var (
	testKey = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	testNonce = []byte{
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xa1,
	}
)

// flipBit returns a copy of b with bit 0 of byte i toggled.
func flipBit(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	p := &DefaultCryptoProvider{}
	aad := []byte("matter payload header")

	for _, pt := range [][]byte{
		nil,
		{},
		[]byte("a"),
		bytes.Repeat([]byte{0xab}, 1),
		bytes.Repeat([]byte{0xcd}, 32),
		bytes.Repeat([]byte{0xef}, 1023),
	} {
		ct, err := p.Encrypt(testKey, testNonce, pt, aad)
		if err != nil {
			t.Fatalf("Encrypt(len=%d): %v", len(pt), err)
		}
		if len(ct) != len(pt)+MatterTagSize {
			t.Fatalf("Encrypt(len=%d): ciphertext len = %d, want %d",
				len(pt), len(ct), len(pt)+MatterTagSize)
		}
		got, err := p.Decrypt(testKey, testNonce, ct, aad)
		if err != nil {
			t.Fatalf("Decrypt(len=%d): %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round-trip(len=%d): got %x, want %x", len(pt), got, pt)
		}
	}
}

func TestDecrypt_RejectsTampering(t *testing.T) {
	p := &DefaultCryptoProvider{}
	aad := []byte("matter aad")
	ct, err := p.Encrypt(testKey, testNonce, []byte("hello matter"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	cases := []struct {
		name                string
		key, nonce, ct, aad []byte
	}{
		{"flipped ciphertext byte", testKey, testNonce, flipBit(ct, 0), aad},
		{"flipped tag byte", testKey, testNonce, flipBit(ct, len(ct)-1), aad},
		{"changed aad", testKey, testNonce, ct, []byte("changed aad!")},
		{"flipped key bit", flipBit(testKey, 0), testNonce, ct, aad},
		{"flipped nonce bit", testKey, flipBit(testNonce, 0), ct, aad},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.Decrypt(tc.key, tc.nonce, tc.ct, tc.aad); err == nil {
				t.Fatal("Decrypt accepted invalid input")
			}
		})
	}
}

func TestEncryptDecrypt_NonceSize(t *testing.T) {
	p := &DefaultCryptoProvider{}

	for _, badLen := range []int{0, 7, 12, 14, 16} {
		nonce := make([]byte, badLen)
		_, err := p.Encrypt(testKey, nonce, []byte("x"), nil)
		if !errors.Is(err, ErrInvalidNonceSize) {
			t.Fatalf("Encrypt(nonce=%d): err=%v, want ErrInvalidNonceSize", badLen, err)
		}
		_, err = p.Decrypt(testKey, nonce, bytes.Repeat([]byte{0}, MatterTagSize+1), nil)
		if !errors.Is(err, ErrInvalidNonceSize) {
			t.Fatalf("Decrypt(nonce=%d): err=%v, want ErrInvalidNonceSize", badLen, err)
		}
	}
}

func TestEncrypt_BadKeySize(t *testing.T) {
	p := &DefaultCryptoProvider{}
	if _, err := p.Encrypt(make([]byte, 15), testNonce, []byte("x"), nil); err == nil {
		t.Fatal("Encrypt accepted 15-byte key")
	}
}

// TestEncrypt_LockedVector regression-locks one (key, nonce, AAD, plaintext)
// quadruple to its AES-128-CCM ciphertext+tag bytes. Catches silent
// behaviour changes in the upstream CCM dependency.
func TestEncrypt_LockedVector(t *testing.T) {
	p := &DefaultCryptoProvider{}
	got, err := p.Encrypt(testKey, testNonce,
		[]byte("the quick brown fox"), []byte("matter"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want, _ := hex.DecodeString("9f821d85d6d5e14e9b5fae4879bbda557ebe4a09bf565c1e77a0f8b444b2d015ff99fd")
	if !bytes.Equal(got, want) {
		t.Fatalf("locked vector drifted:\n got  %x\n want %x", got, want)
	}
}
