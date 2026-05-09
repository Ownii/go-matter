package message

import (
	"bytes"
	"testing"
)

func TestPayloadHeader_MarshalKnownVector(t *testing.T) {
	p := PayloadHeader{
		ExchangeFlags: ExchangeFlagInitiator | ExchangeFlagReliability,
		Opcode:        OpcodePBKDFParamRequest,
		ExchangeID:    0x0001,
		ProtocolID:    ProtocolSecureChannel,
	}
	got, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x05,       // flags: I + R
		0x20,       // opcode: PBKDFParamRequest
		0x01, 0x00, // exchange ID
		0x00, 0x00, // protocol ID: SecureChannel
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestPayloadHeader_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   PayloadHeader
		size int
	}{
		{
			name: "minimal initiator",
			in: PayloadHeader{
				ExchangeFlags: ExchangeFlagInitiator,
				Opcode:        OpcodePBKDFParamRequest,
				ExchangeID:    1,
				ProtocolID:    ProtocolSecureChannel,
			},
			size: 6,
		},
		{
			name: "with vendor",
			in: PayloadHeader{
				ExchangeFlags: ExchangeFlagInitiator | ExchangeFlagVendorPresent,
				Opcode:        OpcodePBKDFParamResponse,
				ExchangeID:    2,
				ProtocolID:    ProtocolInteractionModel,
				VendorID:      0xCAFE,
			},
			size: 8,
		},
		{
			name: "with ack",
			in: PayloadHeader{
				ExchangeFlags: ExchangeFlagAcknowledgement | ExchangeFlagReliability,
				Opcode:        OpcodeMRPStandaloneAck,
				ExchangeID:    3,
				ProtocolID:    ProtocolSecureChannel,
				AckCounter:    0xDEADBEEF,
			},
			size: 10,
		},
		{
			name: "vendor + ack",
			in: PayloadHeader{
				ExchangeFlags: ExchangeFlagInitiator | ExchangeFlagVendorPresent | ExchangeFlagAcknowledgement,
				Opcode:        OpcodeStatusReport,
				ExchangeID:    4,
				ProtocolID:    ProtocolBDX,
				VendorID:      0xFFF1,
				AckCounter:    0xCAFEBABE,
			},
			size: 12,
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
			var got PayloadHeader
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

func TestPayloadHeader_UnmarshalRejectsShort(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00},
		{0x10, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00},                   // V flag set, missing 1 byte of vendor
		{0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD},        // A flag set, missing 1 byte of ack
	}
	for i, b := range cases {
		var p PayloadHeader
		if _, err := p.Unmarshal(b); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
