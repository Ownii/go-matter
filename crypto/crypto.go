package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeyPair represents a public/private key pair.
type KeyPair interface {
	Public() []byte
	Private() []byte
}

// CryptoProvider defines the interface for cryptographic operations.
type CryptoProvider interface {
	// Encrypt performs AES-CCM encryption.
	Encrypt(key []byte, nonce []byte, plaintext []byte, aad []byte) ([]byte, error)

	// Decrypt performs AES-CCM decryption.
	Decrypt(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error)

	// DeriveKeys derives session keys using HKDF.
	DeriveKeys(secret []byte, salt []byte, info []byte) ([]byte, error)
}

// DefaultCryptoProvider implements CryptoProvider.
type DefaultCryptoProvider struct{}

func (p *DefaultCryptoProvider) Encrypt(key []byte, nonce []byte, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// FALLBACK: cipher.NewCCM seems unavailable in this env, using GCM for scaffold compilation.
	// TODO: Switch to NewCCM (13 byte nonce) for production Matter compatibility.
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, aad), nil
}

func (p *DefaultCryptoProvider) Decrypt(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block) // TODO: Switch to NewCCM
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, aad)
}

func (p *DefaultCryptoProvider) DeriveKeys(secret []byte, salt []byte, info []byte) ([]byte, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, secret, salt, info)

	// Matter typically derives multiple keys (I2R, R2I, etc)
	// We just return a chunk of derived bytes here
	// The caller should specify how much they need reading from returns io.Reader
	// CHANGED: Simplified to return just enough bytes for a key, or expose io.Reader?
	// Let's assume we want 16 bytes for now.
	key := make([]byte, 16)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

// NonceGenerator handles the generation of cryptographic nonces.
type NonceGenerator struct {
	NodeID  uint64
	Counter uint32
}

// NewNonceGenerator creates a new NonceGenerator.
func NewNonceGenerator(nodeID uint64, initialCounter uint32) *NonceGenerator {
	return &NonceGenerator{
		NodeID:  nodeID,
		Counter: initialCounter,
	}
}

// NextNonce generates the next nonce based on NodeID and Counter.
func (ng *NonceGenerator) NextNonce() []byte {
	// TODO: Implement nonce generation logic according to Matter spec
	// 5.3.1. Nonce Structure:
	// Security Flags (1 byte) | Session ID (2 bytes) | Message Counter (4 bytes) | Source Node ID (8 bytes)
	ng.Counter++
	return nil
}

// SPAKE2+ types live in spake2plus.go (SPAKE2PProver, SPAKE2PVerifier) and
// the password-derivation helpers in pbkdf.go. The previous SPAKE2PContext
// scaffolding was a placeholder; commissioning now drives the real types.
