package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A test vectors for HKDF-SHA-256.
// https://www.rfc-editor.org/rfc/rfc5869#appendix-A
func TestHKDF_RFC5869Vectors(t *testing.T) {
	tests := []struct {
		name    string
		ikmHex  string
		saltHex string
		infoHex string
		length  int
		okmHex  string
	}{
		{
			name:    "A.1 basic",
			ikmHex:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			saltHex: "000102030405060708090a0b0c",
			infoHex: "f0f1f2f3f4f5f6f7f8f9",
			length:  42,
			okmHex: "3cb25f25faacd57a90434f64d0362f2a" +
				"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
				"34007208d5b887185865",
		},
		{
			name: "A.2 longer inputs and output",
			ikmHex: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			saltHex: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			infoHex: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			length: 82,
			okmHex: "b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f" +
				"1d87",
		},
		{
			name:    "A.3 zero-length salt and info",
			ikmHex:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			saltHex: "",
			infoHex: "",
			length:  42,
			okmHex: "8da4e775a563c18f715f802a063c5a31" +
				"b8a11f5c5ee1879ec3454e5f3c738d2d" +
				"9d201395faa4b61a96c8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ikm, _ := hex.DecodeString(tc.ikmHex)
			salt, _ := hex.DecodeString(tc.saltHex)
			info, _ := hex.DecodeString(tc.infoHex)
			want, _ := hex.DecodeString(tc.okmHex)

			got, err := HKDF(ikm, salt, info, tc.length)
			if err != nil {
				t.Fatalf("HKDF: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("HKDF mismatch\ngot:  %x\nwant: %x", got, want)
			}
		})
	}
}

func TestHKDF_ZeroLength(t *testing.T) {
	got, err := HKDF([]byte("secret"), nil, nil, 0)
	if err != nil {
		t.Fatalf("HKDF length=0: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("HKDF length=0: got %d bytes, want 0", len(got))
	}
}

func TestHKDF_NegativeLength(t *testing.T) {
	if _, err := HKDF([]byte("secret"), nil, nil, -1); err == nil {
		t.Fatal("HKDF length=-1: expected error, got nil")
	}
}

// TestHKDF_DeriveKeysParity locks in that the legacy DeriveKeys wrapper
// still returns the first 16 bytes of HKDF output, so callers (currently
// none in-tree, but the interface is part of the CryptoProvider contract)
// don't see a behaviour change.
func TestHKDF_DeriveKeysParity(t *testing.T) {
	secret := []byte("matter-pase-Ke")
	salt := []byte("salt")
	info := []byte("SessionKeys")

	full, err := HKDF(secret, salt, info, 16)
	if err != nil {
		t.Fatalf("HKDF: %v", err)
	}
	legacy, err := (&DefaultCryptoProvider{}).DeriveKeys(secret, salt, info)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if !bytes.Equal(full, legacy) {
		t.Errorf("DeriveKeys diverged from HKDF(..., 16)\nHKDF:       %x\nDeriveKeys: %x", full, legacy)
	}
}
