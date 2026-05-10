package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	return []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
}

func newTestNonce(t *testing.T) []byte {
	t.Helper()
	return []byte{
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xa1,
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)
	nonce := newTestNonce(t)
	aad := []byte("matter payload header")

	for _, pt := range [][]byte{
		nil,
		{},
		[]byte("a"),
		bytes.Repeat([]byte{0xab}, 1),
		bytes.Repeat([]byte{0xcd}, 32),
		bytes.Repeat([]byte{0xef}, 1023),
	} {
		ct, err := p.Encrypt(key, nonce, pt, aad)
		if err != nil {
			t.Fatalf("Encrypt(len=%d): %v", len(pt), err)
		}
		if len(ct) != len(pt)+MatterTagSize {
			t.Fatalf("Encrypt(len=%d): ciphertext len = %d, want %d",
				len(pt), len(ct), len(pt)+MatterTagSize)
		}
		got, err := p.Decrypt(key, nonce, ct, aad)
		if err != nil {
			t.Fatalf("Decrypt(len=%d): %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round-trip(len=%d): got %x, want %x", len(pt), got, pt)
		}
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)
	nonce := newTestNonce(t)
	aad := []byte("aad")

	ct, err := p.Encrypt(key, nonce, []byte("hello matter"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[0] ^= 0x01
	if _, err := p.Decrypt(key, nonce, ct, aad); err == nil {
		t.Fatal("Decrypt accepted tampered ciphertext byte")
	}
}

func TestDecrypt_TamperedTag(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)
	nonce := newTestNonce(t)
	aad := []byte("aad")

	ct, err := p.Encrypt(key, nonce, []byte("hello matter"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[len(ct)-1] ^= 0x80
	if _, err := p.Decrypt(key, nonce, ct, aad); err == nil {
		t.Fatal("Decrypt accepted tampered tag byte")
	}
}

func TestDecrypt_TamperedAAD(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)
	nonce := newTestNonce(t)

	ct, err := p.Encrypt(key, nonce, []byte("hello matter"), []byte("original aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := p.Decrypt(key, nonce, ct, []byte("changed aad!")); err == nil {
		t.Fatal("Decrypt accepted mismatched AAD")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	p := &DefaultCryptoProvider{}
	nonce := newTestNonce(t)
	aad := []byte("aad")

	ct, err := p.Encrypt(newTestKey(t), nonce, []byte("hello matter"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrong := append([]byte(nil), newTestKey(t)...)
	wrong[0] ^= 0x01
	if _, err := p.Decrypt(wrong, nonce, ct, aad); err == nil {
		t.Fatal("Decrypt accepted wrong key")
	}
}

func TestDecrypt_WrongNonce(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)
	aad := []byte("aad")

	ct, err := p.Encrypt(key, newTestNonce(t), []byte("hello matter"), aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wrong := append([]byte(nil), newTestNonce(t)...)
	wrong[0] ^= 0x01
	if _, err := p.Decrypt(key, wrong, ct, aad); err == nil {
		t.Fatal("Decrypt accepted wrong nonce")
	}
}

func TestEncrypt_NonceSize(t *testing.T) {
	p := &DefaultCryptoProvider{}
	key := newTestKey(t)

	for _, badLen := range []int{0, 7, 12, 14, 16} {
		nonce := make([]byte, badLen)
		_, err := p.Encrypt(key, nonce, []byte("x"), nil)
		if !errors.Is(err, ErrInvalidNonceSize) {
			t.Fatalf("Encrypt(nonce=%d): err=%v, want ErrInvalidNonceSize", badLen, err)
		}
		_, err = p.Decrypt(key, nonce, bytes.Repeat([]byte{0}, MatterTagSize+1), nil)
		if !errors.Is(err, ErrInvalidNonceSize) {
			t.Fatalf("Decrypt(nonce=%d): err=%v, want ErrInvalidNonceSize", badLen, err)
		}
	}
}

func TestEncrypt_BadKeySize(t *testing.T) {
	p := &DefaultCryptoProvider{}
	nonce := newTestNonce(t)

	_, err := p.Encrypt(make([]byte, 15), nonce, []byte("x"), nil)
	if err == nil {
		t.Fatal("Encrypt accepted 15-byte key")
	}
}

// TestEncrypt_LockedVector regression-locks one (key, nonce, AAD, plaintext)
// quadruple to its AES-128-CCM ciphertext+tag bytes. Catches silent
// behaviour changes in the upstream CCM dependency.
func TestEncrypt_LockedVector(t *testing.T) {
	p := &DefaultCryptoProvider{}
	got, err := p.Encrypt(newTestKey(t), newTestNonce(t),
		[]byte("the quick brown fox"), []byte("matter"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want, _ := hex.DecodeString("9f821d85d6d5e14e9b5fae4879bbda557ebe4a09bf565c1e77a0f8b444b2d015ff99fd")
	if !bytes.Equal(got, want) {
		t.Fatalf("locked vector drifted:\n got  %x\n want %x", got, want)
	}
}
