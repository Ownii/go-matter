package message

import (
	"bytes"
	"testing"
)

func TestHeader_MarshalKnownVector(t *testing.T) {
	h := Header{
		Flags:          0,
		SessionID:      0x1234,
		SecurityFlags:  0,
		MessageCounter: 0x12345678,
	}
	got, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x00,                   // flags
		0x34, 0x12,             // session ID (LE)
		0x00,                   // security flags
		0x78, 0x56, 0x34, 0x12, // message counter (LE)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestHeader_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   Header
		size int
	}{
		{
			name: "minimal",
			in: Header{
				SessionID:      0x1234,
				MessageCounter: 0xDEADBEEF,
			},
			size: 8,
		},
		{
			name: "source only",
			in: Header{
				Flags:          MessageFlagSourceNodeIDPresent,
				SessionID:      1,
				MessageCounter: 2,
				SourceNodeID:   0xABCDEF0123456789,
			},
			size: 16,
		},
		{
			name: "source + 64-bit dest",
			in: Header{
				Flags:          MessageFlagSourceNodeIDPresent | MessageFlagDSIZUnicast,
				SessionID:      0xBEEF,
				SecurityFlags:  SecurityFlagControl,
				MessageCounter: 0xCAFEBABE,
				SourceNodeID:   0x1111222233334444,
				DestNodeID:     0x5555666677778888,
			},
			size: 24,
		},
		{
			name: "source + group dest",
			in: Header{
				Flags:          MessageFlagSourceNodeIDPresent | MessageFlagDSIZGroup,
				SessionID:      0,
				MessageCounter: 7,
				SourceNodeID:   42,
				DestNodeID:     0xC0DE,
			},
			size: 18,
		},
		{
			name: "no source, 64-bit dest",
			in: Header{
				Flags:          MessageFlagDSIZUnicast,
				MessageCounter: 1,
				DestNodeID:     0xDEADBEEFCAFEBABE,
			},
			size: 16,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.in.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if len(b) != tc.size {
				t.Fatalf("Marshal length = %d, want %d", len(b), tc.size)
			}

			var got Header
			n, err := got.Unmarshal(b)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if n != tc.size {
				t.Fatalf("Unmarshal consumed %d, want %d", n, tc.size)
			}
			if got != tc.in {
				t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, tc.in)
			}
		})
	}
}

func TestHeader_UnmarshalRejectsShort(t *testing.T) {
	var h Header
	if _, err := h.Unmarshal([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on short input")
	}
}

func TestHeader_MarshalRejectsReservedDSIZ(t *testing.T) {
	h := Header{Flags: MessageFlagDSIZReserved}
	if _, err := h.Marshal(); err == nil {
		t.Fatal("expected error on reserved DSIZ")
	}
}

func TestHeader_UnmarshalRejectsUnknownVersion(t *testing.T) {
	b := []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	var h Header
	if _, err := h.Unmarshal(b); err == nil {
		t.Fatal("expected error on unknown version")
	}
}
