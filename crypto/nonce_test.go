package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

// TestBuildNonce_LockedVector regression-locks one (flags, counter, nodeID)
// triple to its 13-byte Matter §5.3.1 layout. Hand-computed: counter LE,
// node ID LE.
func TestBuildNonce_LockedVector(t *testing.T) {
	got := BuildNonce(0x00, 0x00112233, 0xFEDCBA9876543210)
	want, _ := hex.DecodeString("00332211001032547698badcfe")
	if !bytes.Equal(got, want) {
		t.Fatalf("nonce drifted:\n got  %x\n want %x", got, want)
	}
}

func TestBuildNonce_Length(t *testing.T) {
	if got := len(BuildNonce(0, 0, 0)); got != MatterNonceSize {
		t.Fatalf("nonce length = %d, want %d", got, MatterNonceSize)
	}
}

func TestBuildNonce_FieldPlacement(t *testing.T) {
	n := BuildNonce(0xA5, 0x11223344, 0x0102030405060708)
	if n[0] != 0xA5 {
		t.Fatalf("byte 0 = %#x, want 0xA5", n[0])
	}
	wantCounter := []byte{0x44, 0x33, 0x22, 0x11}
	if !bytes.Equal(n[1:5], wantCounter) {
		t.Fatalf("counter bytes = %x, want %x", n[1:5], wantCounter)
	}
	wantNode := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(n[5:13], wantNode) {
		t.Fatalf("node ID bytes = %x, want %x", n[5:13], wantNode)
	}
}

func TestNonceGenerator_Monotonic(t *testing.T) {
	ng := NewNonceGenerator(0xCAFE, 0)
	seen := make(map[string]struct{})
	for i := 1; i <= 100; i++ {
		n, err := ng.NextNonce()
		if err != nil {
			t.Fatalf("NextNonce #%d: %v", i, err)
		}
		if ng.Counter != uint32(i) {
			t.Fatalf("Counter after #%d = %d, want %d", i, ng.Counter, i)
		}
		if _, dup := seen[string(n)]; dup {
			t.Fatalf("NextNonce #%d returned a duplicate", i)
		}
		seen[string(n)] = struct{}{}
	}
}

func TestNonceGenerator_FixedSourceFlags(t *testing.T) {
	ng := &NonceGenerator{SourceNodeID: 0xDEADBEEF, SecurityFlags: 0x40, Counter: 41}
	a, _ := ng.NextNonce()
	b, _ := ng.NextNonce()

	if a[0] != 0x40 || b[0] != 0x40 {
		t.Fatalf("security flags drifted: a=%#x b=%#x", a[0], b[0])
	}
	if !bytes.Equal(a[5:13], b[5:13]) {
		t.Fatalf("source node ID changed across calls: %x vs %x", a[5:13], b[5:13])
	}
}

func TestNonceGenerator_CounterExhausted(t *testing.T) {
	ng := &NonceGenerator{Counter: math.MaxUint32}
	if _, err := ng.NextNonce(); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("at MaxUint32: err = %v, want ErrCounterExhausted", err)
	}
	if ng.Counter != math.MaxUint32 {
		t.Fatalf("Counter mutated after exhaustion: %d", ng.Counter)
	}
	if _, err := ng.NextNonce(); !errors.Is(err, ErrCounterExhausted) {
		t.Fatal("second call after exhaustion did not stay exhausted")
	}
}

// TestNonceGenerator_AcceptsCCM cross-checks that the generator's output
// is exactly the shape AES-CCM expects — feeding it into the provider
// should round-trip cleanly.
func TestNonceGenerator_AcceptsCCM(t *testing.T) {
	ng := NewNonceGenerator(0xABCDEF0123456789, 0)
	nonce, err := ng.NextNonce()
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	p := &DefaultCryptoProvider{}
	ct, err := p.Encrypt(testKey, nonce, []byte("ping"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := p.Decrypt(testKey, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("round-trip got %q, want ping", got)
	}
}
