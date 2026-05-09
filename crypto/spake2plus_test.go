package crypto

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
)

const testContextString = "CHIP PAKE V1 Commissioning"

func freshProverVerifier(t *testing.T, passcode uint32, salt []byte, iters int, ctx []byte) (*SPAKE2PProver, *SPAKE2PVerifier) {
	t.Helper()
	w0, w1, err := Spake2pW0W1FromPasscode(passcode, salt, iters)
	if err != nil {
		t.Fatalf("Spake2pW0W1FromPasscode: %v", err)
	}
	w0Verifier, L, err := ComputeSPAKE2PVerifierData(passcode, salt, iters)
	if err != nil {
		t.Fatalf("ComputeSPAKE2PVerifierData: %v", err)
	}
	if !bytes.Equal(w0, w0Verifier) {
		t.Fatalf("w0 mismatch between Prover and Verifier derivation")
	}
	prover, err := NewSPAKE2PProver(w0, w1, ctx)
	if err != nil {
		t.Fatalf("NewSPAKE2PProver: %v", err)
	}
	verifier, err := NewSPAKE2PVerifier(w0, L, ctx)
	if err != nil {
		t.Fatalf("NewSPAKE2PVerifier: %v", err)
	}
	return prover, verifier
}

// TestRoundTrip — Prover and Verifier seeded from the same passcode complete
// the protocol with matching Ke and cross-verifying confirmations.
func TestRoundTrip(t *testing.T) {
	prover, verifier := freshProverVerifier(t,
		20202021, []byte("SPAKE2P Key Salt"), 1000, []byte(testContextString))

	pA, err := prover.ComputePA()
	if err != nil {
		t.Fatalf("ComputePA: %v", err)
	}
	pB, err := verifier.ComputePB(pA)
	if err != nil {
		t.Fatalf("ComputePB: %v", err)
	}
	if err := prover.Finalize(pB); err != nil {
		t.Fatalf("Prover.Finalize: %v", err)
	}
	if err := verifier.Finalize(); err != nil {
		t.Fatalf("Verifier.Finalize: %v", err)
	}

	keP, err := prover.SharedKey()
	if err != nil {
		t.Fatalf("Prover.SharedKey: %v", err)
	}
	keV, err := verifier.SharedKey()
	if err != nil {
		t.Fatalf("Verifier.SharedKey: %v", err)
	}
	if !bytes.Equal(keP, keV) {
		t.Errorf("Ke mismatch:\n prover %x\n verif  %x", keP, keV)
	}
	if len(keP) != 16 {
		t.Errorf("Ke length = %d, want 16", len(keP))
	}

	cA, err := prover.ConfirmationA()
	if err != nil {
		t.Fatalf("ConfirmationA: %v", err)
	}
	cB, err := verifier.ConfirmationB()
	if err != nil {
		t.Fatalf("ConfirmationB: %v", err)
	}
	if err := verifier.VerifyConfirmationA(cA); err != nil {
		t.Errorf("VerifyConfirmationA: %v", err)
	}
	if err := prover.VerifyConfirmationB(cB); err != nil {
		t.Errorf("VerifyConfirmationB: %v", err)
	}
}

// TestRoundTrip_WrongPasscode — Verifier seeded from a different passcode
// must fail confirmation without panicking.
func TestRoundTrip_WrongPasscode(t *testing.T) {
	salt := []byte("SPAKE2P Key Salt")
	ctx := []byte(testContextString)

	w0P, w1P, err := Spake2pW0W1FromPasscode(20202021, salt, 1000)
	if err != nil {
		t.Fatalf("prover w0/w1: %v", err)
	}
	w0V, L, err := ComputeSPAKE2PVerifierData(11111111, salt, 1000)
	if err != nil {
		t.Fatalf("verifier (w0,L): %v", err)
	}

	prover, err := NewSPAKE2PProver(w0P, w1P, ctx)
	if err != nil {
		t.Fatalf("NewSPAKE2PProver: %v", err)
	}
	verifier, err := NewSPAKE2PVerifier(w0V, L, ctx)
	if err != nil {
		t.Fatalf("NewSPAKE2PVerifier: %v", err)
	}

	pA, err := prover.ComputePA()
	if err != nil {
		t.Fatalf("ComputePA: %v", err)
	}
	pB, err := verifier.ComputePB(pA)
	if err != nil {
		t.Fatalf("ComputePB: %v", err)
	}
	if err := prover.Finalize(pB); err != nil {
		t.Fatalf("Prover.Finalize: %v", err)
	}
	if err := verifier.Finalize(); err != nil {
		t.Fatalf("Verifier.Finalize: %v", err)
	}

	cA, err := prover.ConfirmationA()
	if err != nil {
		t.Fatalf("ConfirmationA: %v", err)
	}
	cB, err := verifier.ConfirmationB()
	if err != nil {
		t.Fatalf("ConfirmationB: %v", err)
	}
	if err := verifier.VerifyConfirmationA(cA); err == nil {
		t.Errorf("VerifyConfirmationA must fail for wrong passcode")
	}
	if err := prover.VerifyConfirmationB(cB); err == nil {
		t.Errorf("VerifyConfirmationB must fail for wrong passcode")
	}

	keP, _ := prover.SharedKey()
	keV, _ := verifier.SharedKey()
	if bytes.Equal(keP, keV) {
		t.Errorf("Ke must differ for mismatched passcodes")
	}
}

// TestRejectInvalidPoint — off-curve and malformed peer points are rejected.
func TestRejectInvalidPoint(t *testing.T) {
	prover, verifier := freshProverVerifier(t,
		20202021, []byte("SPAKE2P Key Salt"), 1000, []byte(testContextString))

	if _, err := verifier.ComputePB([]byte{0x04, 0x00, 0x01}); err == nil {
		t.Errorf("verifier accepted truncated pA")
	}
	bogus := make([]byte, 65)
	bogus[0] = 0x04 // uncompressed prefix, but rest is zero -> off-curve
	if _, err := verifier.ComputePB(bogus); err == nil {
		t.Errorf("verifier accepted off-curve pA")
	}

	pA, err := prover.ComputePA()
	if err != nil {
		t.Fatalf("ComputePA: %v", err)
	}
	if err := prover.Finalize(append([]byte{}, bogus...)); err == nil {
		t.Errorf("prover accepted off-curve pB")
	}
	_ = pA

	// Constructor must reject an off-curve L.
	w0, _, err := Spake2pW0W1FromPasscode(20202021, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		t.Fatalf("derive w0: %v", err)
	}
	if _, err := NewSPAKE2PVerifier(w0, bogus, []byte(testContextString)); err == nil {
		t.Errorf("NewSPAKE2PVerifier accepted off-curve L")
	}
}

// TestEarlyAccessors — calling SharedKey / Confirmation* before Finalize is
// an error, not a panic.
func TestEarlyAccessors(t *testing.T) {
	prover, verifier := freshProverVerifier(t,
		20202021, []byte("SPAKE2P Key Salt"), 1000, []byte(testContextString))

	if _, err := prover.SharedKey(); err == nil {
		t.Error("Prover.SharedKey should fail before Finalize")
	}
	if _, err := verifier.SharedKey(); err == nil {
		t.Error("Verifier.SharedKey should fail before Finalize")
	}
	if _, err := prover.ConfirmationA(); err == nil {
		t.Error("Prover.ConfirmationA should fail before Finalize")
	}
	if _, err := verifier.ConfirmationB(); err == nil {
		t.Error("Verifier.ConfirmationB should fail before Finalize")
	}
	if err := prover.VerifyConfirmationB(make([]byte, 32)); err == nil {
		t.Error("VerifyConfirmationB should fail before Finalize")
	}
	if err := verifier.VerifyConfirmationA(make([]byte, 32)); err == nil {
		t.Error("VerifyConfirmationA should fail before Finalize")
	}
}

// counterReader produces deterministic bytes for transcript-locking tests.
// It implements io.Reader; each Read fills with a counter so two parallel
// reads of the same length produce identical output.
type counterReader struct{ counter uint64 }

func (c *counterReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c.counter)
		c.counter++
	}
	return len(p), nil
}

func withDeterministicRand(t *testing.T, seed uint64) func() {
	t.Helper()
	old := spakeRandReader
	spakeRandReader = &counterReader{counter: seed}
	return func() { spakeRandReader = old }
}

// TestTranscriptDeterminism — with the secret-scalar source pinned, the
// protocol's wire output (pA, pB, Ke, cA, cB) is byte-identical across
// runs. Locks bytes against drift; if SPAKE2+ math/encoding changes
// unexpectedly, this test fails and must be cross-checked against
// connectedhomeip before being re-pinned.
func TestTranscriptDeterminism(t *testing.T) {
	salt := []byte("SPAKE2P Key Salt")
	ctxStr := []byte(testContextString)

	type result struct {
		pA, pB, Ke, cA, cB string
	}
	run := func() result {
		defer withDeterministicRand(t, 0x42)()
		prover, verifier := freshProverVerifier(t, 20202021, salt, 1000, ctxStr)
		pA, err := prover.ComputePA()
		if err != nil {
			t.Fatalf("ComputePA: %v", err)
		}
		pB, err := verifier.ComputePB(pA)
		if err != nil {
			t.Fatalf("ComputePB: %v", err)
		}
		if err := prover.Finalize(pB); err != nil {
			t.Fatalf("Prover.Finalize: %v", err)
		}
		if err := verifier.Finalize(); err != nil {
			t.Fatalf("Verifier.Finalize: %v", err)
		}
		ke, _ := prover.SharedKey()
		cA, _ := prover.ConfirmationA()
		cB, _ := verifier.ConfirmationB()
		return result{
			pA: hex.EncodeToString(pA),
			pB: hex.EncodeToString(pB),
			Ke: hex.EncodeToString(ke),
			cA: hex.EncodeToString(cA),
			cB: hex.EncodeToString(cB),
		}
	}

	first := run()
	second := run()
	if first != second {
		t.Fatalf("non-deterministic output:\n first  %+v\n second %+v", first, second)
	}

	// Hard regression lock: any change to TT layout, M/N constants, KcA/KcB
	// HKDF info, or scalar handling will break these. If a future commit
	// legitimately needs to alter the wire output, re-pin these only after
	// cross-checking against connectedhomeip's PASE test fixtures.
	want := result{
		pA: "04d8d3b4d9131f66fcdfcead82ac900835101e28d1ffbc5b455c06fd8c85ea6dab094aece3bb850d40e3b9093bd4fa03dba7e9f3f2b452dff2c57a96a855db2b18",
		pB: "045e8f9fc19bcd3924a68f19eabd049478bcf81faa4d8535750bb1be5aa405c7e98c2b49c43ce3d57d1a535efbfee95d9313a4a0ad84a47d471d3a8341cc5b5204",
		Ke: "bcdbcb1211c4f67edadc170e9ddd175e",
		cA: "a584b72a7b40391c65eaff085573dc5321f50bb7b4189cdf0b36409f98de868b",
		cB: "dafa074e1f6cd9ed0ef1a6a7bb262e0c51f4083a9119b92ea3838d55eccfbd22",
	}
	if first != want {
		t.Errorf("transcript drifted from locked vector:\n got  %+v\n want %+v", first, want)
	}
}

// TestComputePATwiceIsIdempotentScalar — guard against Finalize accidentally
// regenerating x.
func TestProverFinalizeRequiresPA(t *testing.T) {
	w0, w1, err := Spake2pW0W1FromPasscode(20202021, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	prover, err := NewSPAKE2PProver(w0, w1, []byte(testContextString))
	if err != nil {
		t.Fatalf("NewSPAKE2PProver: %v", err)
	}
	pBValid := goodPointBytes(t)
	if err := prover.Finalize(pBValid); err == nil {
		t.Errorf("Finalize without ComputePA must fail")
	}
}

func goodPointBytes(t *testing.T) []byte {
	t.Helper()
	curve := elliptic.P256()
	scalar := make([]byte, 32)
	binary.BigEndian.PutUint32(scalar[28:], 1)
	x, y := curve.ScalarBaseMult(scalar)
	return elliptic.Marshal(curve, x, y)
}

// Smoke test: counterReader returns predictable bytes and the test helper
// io.Reader interface is wired correctly.
var _ io.Reader = (*counterReader)(nil)
