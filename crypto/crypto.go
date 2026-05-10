package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
	"golang.org/x/crypto/hkdf"
)

// MatterNonceSize is the fixed 13-byte AEAD nonce mandated by Matter §5.3.
const MatterNonceSize = 13

// MatterTagSize is the 16-byte authentication tag mandated by Matter §5.3.
const MatterTagSize = 16

// ErrInvalidNonceSize is returned when an AES-CCM nonce is not 13 bytes.
var ErrInvalidNonceSize = errors.New("crypto: nonce must be 13 bytes per Matter §5.3")

// KeyPair represents a public/private key pair.
type KeyPair interface {
	Public() []byte
	Private() []byte
}

// CryptoProvider defines the interface for cryptographic operations.
type CryptoProvider interface {
	// Encrypt seals plaintext with AES-128-CCM (Matter §5.3); the
	// authentication tag is appended to the returned ciphertext. Returns
	// ErrInvalidNonceSize when len(nonce) != MatterNonceSize.
	Encrypt(key []byte, nonce []byte, plaintext []byte, aad []byte) ([]byte, error)

	// Decrypt opens an AES-128-CCM ciphertext that carries a trailing
	// authentication tag (Matter §5.3). Returns ErrInvalidNonceSize when
	// len(nonce) != MatterNonceSize, or an auth-failure error from the
	// underlying AEAD.
	Decrypt(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error)

	// DeriveKeys derives session keys using HKDF.
	DeriveKeys(secret []byte, salt []byte, info []byte) ([]byte, error)
}

// DefaultCryptoProvider implements CryptoProvider.
type DefaultCryptoProvider struct{}

func newMatterCCM(key, nonce []byte) (cipher.AEAD, error) {
	if len(nonce) != MatterNonceSize {
		return nil, ErrInvalidNonceSize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes key: %w", err)
	}
	return ccm.NewCCM(block, MatterTagSize, MatterNonceSize)
}

func (p *DefaultCryptoProvider) Encrypt(key []byte, nonce []byte, plaintext []byte, aad []byte) ([]byte, error) {
	aead, err := newMatterCCM(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (p *DefaultCryptoProvider) Decrypt(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	aead, err := newMatterCCM(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
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

// ErrCounterExhausted is returned when the 32-bit outbound message
// counter would wrap; session keys must be retired before further use.
var ErrCounterExhausted = errors.New("crypto: outbound message counter exhausted")

// BuildNonce assembles the 13-byte AES-CCM nonce for a unicast secured
// frame per Matter §5.3.1: SecurityFlags(1) ‖ MessageCounter(4 LE) ‖
// SourceNodeID(8 LE). The receiver reconstructs the same bytes from the
// cleartext message header before decrypting.
func BuildNonce(securityFlags byte, messageCounter uint32, sourceNodeID uint64) []byte {
	nonce := make([]byte, MatterNonceSize)
	nonce[0] = securityFlags
	binary.LittleEndian.PutUint32(nonce[1:5], messageCounter)
	binary.LittleEndian.PutUint64(nonce[5:13], sourceNodeID)
	return nonce
}

// NonceGenerator produces successive outbound nonces for a single secure
// session. Receivers should not use this type — they rebuild nonces from
// the inbound message header via BuildNonce directly.
//
// Not safe for concurrent use: callers must serialize NextNonce per
// generator. Concurrent calls could otherwise emit duplicate nonces under
// the same key, which is fatal for AES-CCM (Matter §4.5.1.1).
type NonceGenerator struct {
	SourceNodeID  uint64
	SecurityFlags byte
	Counter       uint32
}

// NextNonce increments the message counter and returns the nonce for the
// new value. Returns ErrCounterExhausted before the counter would wrap.
func (ng *NonceGenerator) NextNonce() ([]byte, error) {
	if ng.Counter == math.MaxUint32 {
		return nil, ErrCounterExhausted
	}
	ng.Counter++
	return BuildNonce(ng.SecurityFlags, ng.Counter, ng.SourceNodeID), nil
}

// SPAKE2+ types live in spake2plus.go (SPAKE2PProver, SPAKE2PVerifier) and
// the password-derivation helpers in pbkdf.go. The previous SPAKE2PContext
// scaffolding was a placeholder; commissioning now drives the real types.
