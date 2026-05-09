// SPAKE2+ implementation adapted from github.com/tom-code/gomat
// (spake2p.go and util.go).
//
// Copyright (c) 2023, Tomas Petrilak
// SPDX-License-Identifier: BSD-2-Clause
//
// Redistributed under the BSD 2-Clause License. The full license text and
// upstream attribution live in /THIRD_PARTY_LICENSES at the repository root.
//
// Differences from upstream:
//   - Single SpakeCtx split into SPAKE2PProver (A-side) and SPAKE2PVerifier
//     (B-side). The Verifier only ever holds (w0, L); w1 is Prover-only, which
//     is the whole point of the "augmented" PAKE.
//   - Idiomatic Go names; helpers folded in under a "spake" prefix.
//   - Off-curve points are rejected at unmarshal time instead of producing
//     nil-deref panics later.
//   - Confirmation values are compared with crypto/subtle, not bytes.Equal.
//   - M and N are decompressed once at init() and validated on the curve.
//
// Wire output (TT layout, w0/w1 byte widths, KcA/KcB HKDF salt+info,
// SessionKeys derivation) is preserved byte-for-byte from the upstream so
// our Prover/Verifier remain interoperable with gomat's SpakeCtx — covered
// by TestInteropWithGomat in spake2plus_test.go.

package crypto

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// ErrInvalidPoint is returned when a peer's pA / pB does not unmarshal as a
// point on the P-256 curve.
var ErrInvalidPoint = errors.New("crypto/spake2plus: peer point is not on P-256")

// ErrConfirmationMismatch is returned when a confirmation MAC does not match
// the value computed locally.
var ErrConfirmationMismatch = errors.New("crypto/spake2plus: confirmation MAC mismatch")

// errNotFinalized is returned when SharedKey / ConfirmationA / ConfirmationB
// are called before Finalize.
var errNotFinalized = errors.New("crypto/spake2plus: Finalize has not been called")

// spakeRandReader is the source of secret scalars. Production callers leave
// it at rand.Reader; tests swap it for a deterministic reader to lock the
// transcript.
var spakeRandReader io.Reader = rand.Reader

// spake2pCurve is P-256, the only curve Matter §3.10 mandates.
//
// crypto/elliptic is deprecated in Go 1.21+ in favour of crypto/ecdh, but
// ecdh does not expose the arbitrary point arithmetic SPAKE2+ needs
// (X = x·G + w0·M, etc.), so we stay on crypto/elliptic.
var spake2pCurve = elliptic.P256()

// M and N are the SPAKE2+ generator points for P-256 from RFC 9383 §4.
var (
	spakeMx, spakeMy *big.Int
	spakeNx, spakeNy *big.Int
	spakeMBytes      []byte
	spakeNBytes      []byte
)

func init() {
	const (
		mHex = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
		nHex = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
	)

	mBin, err := hex.DecodeString(mHex)
	if err != nil {
		panic(fmt.Sprintf("crypto/spake2plus: bad M hex: %v", err))
	}
	spakeMx, spakeMy = elliptic.UnmarshalCompressed(spake2pCurve, mBin)
	if spakeMx == nil || !spake2pCurve.IsOnCurve(spakeMx, spakeMy) {
		panic("crypto/spake2plus: M is not on P-256")
	}
	spakeMBytes = elliptic.Marshal(spake2pCurve, spakeMx, spakeMy)

	nBin, err := hex.DecodeString(nHex)
	if err != nil {
		panic(fmt.Sprintf("crypto/spake2plus: bad N hex: %v", err))
	}
	spakeNx, spakeNy = elliptic.UnmarshalCompressed(spake2pCurve, nBin)
	if spakeNx == nil || !spake2pCurve.IsOnCurve(spakeNx, spakeNy) {
		panic("crypto/spake2plus: N is not on P-256")
	}
	spakeNBytes = elliptic.Marshal(spake2pCurve, spakeNx, spakeNy)
}

func spakeSha256Sum(in []byte) []byte {
	s := sha256.New()
	s.Write(in)
	return s.Sum(nil)
}

func spakeHmacSha256(key, in []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(in)
	return mac.Sum(nil)
}

func spakeHkdfSha256(secret, salt, info []byte, size int) ([]byte, error) {
	engine := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, size)
	if _, err := io.ReadFull(engine, out); err != nil {
		return nil, fmt.Errorf("crypto/spake2plus: HKDF expand: %w", err)
	}
	return out, nil
}

func spakeRandomScalar() (*big.Int, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(spakeRandReader, buf); err != nil {
		return nil, fmt.Errorf("crypto/spake2plus: random: %w", err)
	}
	return new(big.Int).SetBytes(buf), nil
}

func spakeSerializeBytes(buf *bytes.Buffer, p []byte) {
	binary.Write(buf, binary.LittleEndian, uint64(len(p)))
	buf.Write(p)
}

// spakeBuildTT assembles the SPAKE2+ transcript per Matter §3.10.3 / RFC 9383
// §3.3 (idProver and idVerifier are empty strings for Matter PASE).
func spakeBuildTT(contextHash, x, y, z, v, w0 []byte) []byte {
	var buf bytes.Buffer
	spakeSerializeBytes(&buf, contextHash)
	spakeSerializeBytes(&buf, nil) // idProver = ""
	spakeSerializeBytes(&buf, nil) // idVerifier = ""
	spakeSerializeBytes(&buf, spakeMBytes)
	spakeSerializeBytes(&buf, spakeNBytes)
	spakeSerializeBytes(&buf, x)
	spakeSerializeBytes(&buf, y)
	spakeSerializeBytes(&buf, z)
	spakeSerializeBytes(&buf, v)
	spakeSerializeBytes(&buf, w0)
	return buf.Bytes()
}

// unmarshalP256Point decodes a 65-byte uncompressed point and rejects anything
// off-curve or malformed.
func unmarshalP256Point(in []byte) (*big.Int, *big.Int, error) {
	x, y := elliptic.Unmarshal(spake2pCurve, in)
	if x == nil || !spake2pCurve.IsOnCurve(x, y) {
		return nil, nil, ErrInvalidPoint
	}
	return x, y, nil
}

// SPAKE2PProver is the A-side (Initiator / Commissioner) of a Matter PASE
// SPAKE2+ exchange. It holds w0 and w1 derived from the shared passcode.
type SPAKE2PProver struct {
	w0      []byte
	w1      []byte
	context []byte

	x      *big.Int
	pA     []byte
	pB     []byte
	ke     []byte
	cA, cB []byte

	finalized bool
}

// NewSPAKE2PProver builds a Prover from (w0, w1) reduced mod p256.N (typically
// the output of ComputeSPAKE2PVerifierData / Spake2pW0W1FromPasscode) and the
// raw Matter PASE context bytes (hashed inside Finalize).
func NewSPAKE2PProver(w0, w1, context []byte) (*SPAKE2PProver, error) {
	if len(w0) == 0 || len(w1) == 0 {
		return nil, errors.New("crypto/spake2plus: w0 and w1 must be non-empty")
	}
	return &SPAKE2PProver{
		w0:      append([]byte(nil), w0...),
		w1:      append([]byte(nil), w1...),
		context: append([]byte(nil), context...),
	}, nil
}

// ComputePA generates the ephemeral scalar x and returns
// pA = x·G + w0·M as a 65-byte uncompressed P-256 point.
func (p *SPAKE2PProver) ComputePA() ([]byte, error) {
	x, err := spakeRandomScalar()
	if err != nil {
		return nil, err
	}
	p.x = x

	tx, ty := spake2pCurve.ScalarBaseMult(x.Bytes())
	mx, my := spake2pCurve.ScalarMult(spakeMx, spakeMy, p.w0)
	pAx, pAy := spake2pCurve.Add(tx, ty, mx, my)
	p.pA = elliptic.Marshal(spake2pCurve, pAx, pAy)
	return append([]byte(nil), p.pA...), nil
}

// Finalize ingests the peer's pB, computes Z and V, derives Ke, Ka, KcA, KcB,
// and produces both confirmation MACs.
func (p *SPAKE2PProver) Finalize(pB []byte) error {
	if p.x == nil {
		return errors.New("crypto/spake2plus: ComputePA must be called before Finalize")
	}
	pBx, pBy, err := unmarshalP256Point(pB)
	if err != nil {
		return err
	}
	p.pB = append([]byte(nil), pB...)

	// Z = x · (pB − w0·N)
	// V = w1 · (pB − w0·N)
	wnx, wny := spake2pCurve.ScalarMult(spakeNx, spakeNy, p.w0)
	wny = new(big.Int).Mod(new(big.Int).Neg(wny), spake2pCurve.Params().P)
	dx, dy := spake2pCurve.Add(pBx, pBy, wnx, wny)
	zx, zy := spake2pCurve.ScalarMult(dx, dy, p.x.Bytes())
	vx, vy := spake2pCurve.ScalarMult(dx, dy, p.w1)
	z := elliptic.Marshal(spake2pCurve, zx, zy)
	v := elliptic.Marshal(spake2pCurve, vx, vy)

	return p.deriveKeys(z, v)
}

func (p *SPAKE2PProver) deriveKeys(z, v []byte) error {
	contextHash := spakeSha256Sum(p.context)
	tt := spakeBuildTT(contextHash, p.pA, p.pB, z, v, p.w0)
	ttHash := spakeSha256Sum(tt)
	ka := ttHash[:16]
	p.ke = append([]byte(nil), ttHash[16:32]...)

	confirmKeys, err := spakeHkdfSha256(ka, nil, []byte("ConfirmationKeys"), 32)
	if err != nil {
		return err
	}
	p.cA = spakeHmacSha256(confirmKeys[:16], p.pB)
	p.cB = spakeHmacSha256(confirmKeys[16:], p.pA)
	p.finalized = true
	return nil
}

// ConfirmationA returns cA, the MAC the Prover sends to the Verifier.
func (p *SPAKE2PProver) ConfirmationA() ([]byte, error) {
	if !p.finalized {
		return nil, errNotFinalized
	}
	return append([]byte(nil), p.cA...), nil
}

// VerifyConfirmationB constant-time-compares the Verifier's cB against the
// locally derived value.
func (p *SPAKE2PProver) VerifyConfirmationB(cB []byte) error {
	if !p.finalized {
		return errNotFinalized
	}
	if subtle.ConstantTimeCompare(p.cB, cB) != 1 {
		return ErrConfirmationMismatch
	}
	return nil
}

// SharedKey returns Ke, the 16-byte shared secret used to seed Matter session
// keys (I2RKey / R2IKey / AttestationChallenge).
func (p *SPAKE2PProver) SharedKey() ([]byte, error) {
	if !p.finalized {
		return nil, errNotFinalized
	}
	return append([]byte(nil), p.ke...), nil
}

// SPAKE2PVerifier is the B-side (Responder / Commissionee) of a Matter PASE
// SPAKE2+ exchange. It holds (w0, L) — the device's persisted verifier — and
// never sees the original passcode or w1.
type SPAKE2PVerifier struct {
	w0      []byte
	lBytes  []byte // 65-byte uncompressed L = w1·G
	lx, ly  *big.Int
	context []byte

	y      *big.Int
	pA     []byte
	pB     []byte
	zV, vV []byte // pre-computed Z and V points (uncompressed, 65 bytes each)
	ke     []byte
	cA, cB []byte

	finalized bool
}

// NewSPAKE2PVerifier builds a Verifier from (w0, L) (typically produced once
// at provisioning time by ComputeSPAKE2PVerifierData) and the raw Matter PASE
// context bytes.
func NewSPAKE2PVerifier(w0, l, context []byte) (*SPAKE2PVerifier, error) {
	if len(w0) == 0 {
		return nil, errors.New("crypto/spake2plus: w0 must be non-empty")
	}
	lx, ly, err := unmarshalP256Point(l)
	if err != nil {
		return nil, fmt.Errorf("crypto/spake2plus: L: %w", err)
	}
	return &SPAKE2PVerifier{
		w0:      append([]byte(nil), w0...),
		lBytes:  append([]byte(nil), l...),
		lx:      lx,
		ly:      ly,
		context: append([]byte(nil), context...),
	}, nil
}

// ComputePB ingests the peer's pA, generates the ephemeral scalar y, and
// returns pB = y·G + w0·N. It also pre-computes Z = y·(pA − w0·M) and
// V = y·L so Finalize can derive keys without further EC work.
func (v *SPAKE2PVerifier) ComputePB(pA []byte) ([]byte, error) {
	pAx, pAy, err := unmarshalP256Point(pA)
	if err != nil {
		return nil, err
	}
	v.pA = append([]byte(nil), pA...)

	y, err := spakeRandomScalar()
	if err != nil {
		return nil, err
	}
	v.y = y

	// pB = y·G + w0·N
	npx, npy := spake2pCurve.ScalarMult(spakeNx, spakeNy, v.w0)
	tpx, tpy := spake2pCurve.ScalarBaseMult(y.Bytes())
	pBx, pBy := spake2pCurve.Add(tpx, tpy, npx, npy)
	v.pB = elliptic.Marshal(spake2pCurve, pBx, pBy)

	// Z = y · (pA − w0·M); V = y · L
	wmx, wmy := spake2pCurve.ScalarMult(spakeMx, spakeMy, v.w0)
	wmy = new(big.Int).Mod(new(big.Int).Neg(wmy), spake2pCurve.Params().P)
	dx, dy := spake2pCurve.Add(pAx, pAy, wmx, wmy)
	zx, zy := spake2pCurve.ScalarMult(dx, dy, y.Bytes())
	vx, vy := spake2pCurve.ScalarMult(v.lx, v.ly, y.Bytes())
	v.zV = elliptic.Marshal(spake2pCurve, zx, zy)
	v.vV = elliptic.Marshal(spake2pCurve, vx, vy)

	return append([]byte(nil), v.pB...), nil
}

// Finalize derives Ke, Ka, KcA, KcB and the two confirmation MACs from the
// transcript pre-computed by ComputePB.
func (v *SPAKE2PVerifier) Finalize() error {
	if v.zV == nil || v.vV == nil {
		return errors.New("crypto/spake2plus: ComputePB must be called before Finalize")
	}
	contextHash := spakeSha256Sum(v.context)
	tt := spakeBuildTT(contextHash, v.pA, v.pB, v.zV, v.vV, v.w0)
	ttHash := spakeSha256Sum(tt)
	ka := ttHash[:16]
	v.ke = append([]byte(nil), ttHash[16:32]...)

	confirmKeys, err := spakeHkdfSha256(ka, nil, []byte("ConfirmationKeys"), 32)
	if err != nil {
		return err
	}
	v.cA = spakeHmacSha256(confirmKeys[:16], v.pB)
	v.cB = spakeHmacSha256(confirmKeys[16:], v.pA)
	v.finalized = true
	return nil
}

// ConfirmationB returns cB, the MAC the Verifier sends back to the Prover.
func (v *SPAKE2PVerifier) ConfirmationB() ([]byte, error) {
	if !v.finalized {
		return nil, errNotFinalized
	}
	return append([]byte(nil), v.cB...), nil
}

// VerifyConfirmationA constant-time-compares the Prover's cA against the
// locally derived value.
func (v *SPAKE2PVerifier) VerifyConfirmationA(cA []byte) error {
	if !v.finalized {
		return errNotFinalized
	}
	if subtle.ConstantTimeCompare(v.cA, cA) != 1 {
		return ErrConfirmationMismatch
	}
	return nil
}

// SharedKey returns Ke, the 16-byte shared secret. Identical to the Prover's
// Ke when both sides used the same passcode.
func (v *SPAKE2PVerifier) SharedKey() ([]byte, error) {
	if !v.finalized {
		return nil, errNotFinalized
	}
	return append([]byte(nil), v.ke...), nil
}
