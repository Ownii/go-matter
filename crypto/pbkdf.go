package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2HmacSha256 is a thin wrapper around golang.org/x/crypto/pbkdf2 that
// fixes the hash to SHA-256 (the only PRF Matter §3.9 permits). dkLen is the
// requested derived-key length in bytes.
func PBKDF2HmacSha256(password, salt []byte, iterations, dkLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, dkLen, sha256.New)
}

// Spake2pW0W1FromPasscode runs Matter §3.10.1 password derivation: PBKDF2-
// HMAC-SHA256 over little-endian uint32(passcode) for `iterations` rounds
// producing 80 bytes, split into two 40-byte halves and reduced mod n
// (P-256 group order) to give w0 and w1.
//
// Both outputs are encoded as the minimal big-endian byte string of the
// reduced scalar (matching gomat / RFC 9383 scalar encoding via
// big.Int.Bytes()). They may therefore be shorter than 32 bytes when the
// reduced value has leading zero bytes — acceptable for the elliptic curve
// math but a known interop hazard against Matter implementations that
// fixed-width-encode in the SPAKE2+ TT.
//
// TODO: cross-check fixed-width encoding against connectedhomeip's
// kSpake2p_WS_Length and switch to FillBytes(make([]byte, 32), …) if the
// spec mandates it.
func Spake2pW0W1FromPasscode(passcode uint32, salt []byte, iterations int) (w0, w1 []byte, err error) {
	if iterations <= 0 {
		return nil, nil, errors.New("crypto/spake2plus: iterations must be > 0")
	}
	if len(salt) == 0 {
		return nil, nil, errors.New("crypto/spake2plus: salt must be non-empty")
	}
	pwd := make([]byte, 4)
	binary.LittleEndian.PutUint32(pwd, passcode)
	ws := PBKDF2HmacSha256(pwd, salt, iterations, 80)

	n := elliptic.P256().Params().N
	w0Big := new(big.Int).SetBytes(ws[:40])
	w0Big.Mod(w0Big, n)
	w1Big := new(big.Int).SetBytes(ws[40:])
	w1Big.Mod(w1Big, n)
	return w0Big.Bytes(), w1Big.Bytes(), nil
}

// ComputeSPAKE2PVerifierData runs Spake2pW0W1FromPasscode and returns
// (w0, L) — the verifier-side data a Matter device persists at provisioning
// time. L = w1·G is the 65-byte uncompressed P-256 point.
func ComputeSPAKE2PVerifierData(passcode uint32, salt []byte, iterations int) (w0, L []byte, err error) {
	w0, w1, err := Spake2pW0W1FromPasscode(passcode, salt, iterations)
	if err != nil {
		return nil, nil, err
	}
	curve := elliptic.P256()
	lx, ly := curve.ScalarBaseMult(w1)
	L = elliptic.Marshal(curve, lx, ly)
	return w0, L, nil
}
