package message

import (
	"bytes"
	"testing"
)

func TestFrame_RoundTrip(t *testing.T) {
	in := &Frame{
		Header: Header{
			Flags:          MessageFlagSourceNodeIDPresent,
			SessionID:      0,
			SecurityFlags:  SessionTypeUnicast,
			MessageCounter: 0x00000001,
			SourceNodeID:   0x1122334455667788,
		},
		PayloadHeader: PayloadHeader{
			ExchangeFlags: ExchangeFlagInitiator | ExchangeFlagReliability,
			Opcode:        OpcodePBKDFParamRequest,
			ExchangeID:    1,
			ProtocolID:    ProtocolSecureChannel,
		},
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	wire, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	out, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if out.Header != in.Header {
		t.Errorf("Header mismatch:\n got %+v\nwant %+v", out.Header, in.Header)
	}
	if out.PayloadHeader != in.PayloadHeader {
		t.Errorf("PayloadHeader mismatch:\n got %+v\nwant %+v", out.PayloadHeader, in.PayloadHeader)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Errorf("Payload mismatch: got %x want %x", out.Payload, in.Payload)
	}

	// Re-encode and verify byte-for-byte stability.
	wire2, err := out.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(wire, wire2) {
		t.Errorf("re-encode not stable:\n  first %x\n second %x", wire, wire2)
	}
}

func TestFrame_DecodeNoPayload(t *testing.T) {
	in := &Frame{
		Header: Header{
			MessageCounter: 5,
		},
		PayloadHeader: PayloadHeader{
			ExchangeFlags: ExchangeFlagAcknowledgement,
			Opcode:        OpcodeMRPStandaloneAck,
			ExchangeID:    9,
			ProtocolID:    ProtocolSecureChannel,
			AckCounter:    1,
		},
	}
	wire, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Payload) != 0 {
		t.Errorf("expected empty payload, got %x", out.Payload)
	}
}

func TestFrame_DecodeErrorPropagates(t *testing.T) {
	if _, err := Decode([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error on truncated header")
	}
}
