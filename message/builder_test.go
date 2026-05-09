package message

import (
	"bytes"
	"testing"
)

type tlvPayload struct {
	A uint16 `tlv:"1"`
	B []byte `tlv:"2"`
}

func TestBuilder_HappyPath(t *testing.T) {
	frame, err := NewBuilder().
		Unsecured().
		MessageCounter(42).
		Protocol(ProtocolSecureChannel).
		Opcode(OpcodePBKDFParamRequest).
		ExchangeID(7).
		Initiator().
		RequestAck().
		Payload(&tlvPayload{A: 0xBEEF, B: []byte{1, 2, 3}}).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if frame.Header.SessionID != 0 {
		t.Errorf("SessionID = %d, want 0 for unsecured", frame.Header.SessionID)
	}
	if frame.Header.MessageCounter != 42 {
		t.Errorf("MessageCounter = %d, want 42", frame.Header.MessageCounter)
	}
	if frame.PayloadHeader.ProtocolID != ProtocolSecureChannel {
		t.Errorf("ProtocolID = %d, want SecureChannel", frame.PayloadHeader.ProtocolID)
	}
	if frame.PayloadHeader.Opcode != OpcodePBKDFParamRequest {
		t.Errorf("Opcode = %#x, want PBKDFParamRequest", frame.PayloadHeader.Opcode)
	}
	if frame.PayloadHeader.ExchangeID != 7 {
		t.Errorf("ExchangeID = %d, want 7", frame.PayloadHeader.ExchangeID)
	}
	want := ExchangeFlagInitiator | ExchangeFlagReliability
	if frame.PayloadHeader.ExchangeFlags != want {
		t.Errorf("ExchangeFlags = %#x, want %#x", frame.PayloadHeader.ExchangeFlags, want)
	}
	if len(frame.Payload) == 0 {
		t.Error("Payload empty after marshal")
	}
}

func TestBuilder_PayloadByteSlicePassthrough(t *testing.T) {
	raw := []byte{0xAA, 0xBB, 0xCC}
	frame, err := NewBuilder().
		Protocol(ProtocolSecureChannel).
		Opcode(OpcodeMRPStandaloneAck).
		Payload(raw).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(frame.Payload, raw) {
		t.Errorf("Payload = %x, want %x", frame.Payload, raw)
	}
}

func TestBuilder_PayloadNil(t *testing.T) {
	frame, err := NewBuilder().
		Protocol(ProtocolSecureChannel).
		Opcode(OpcodeMRPStandaloneAck).
		Payload(nil).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if frame.Payload != nil {
		t.Errorf("Payload = %x, want nil", frame.Payload)
	}
}

func TestBuilder_PayloadMarshalErrorPropagates(t *testing.T) {
	// channels are not encodable by tlv.Marshal — encodeValue's default branch
	// returns "unsupported type".
	ch := make(chan int)
	_, err := NewBuilder().
		Protocol(ProtocolSecureChannel).
		Opcode(OpcodePBKDFParamRequest).
		Payload(ch).
		Build()
	if err == nil {
		t.Fatal("expected payload marshal error")
	}
}

func TestBuilder_MissingProtocolAndOpcode(t *testing.T) {
	if _, err := NewBuilder().Build(); err == nil {
		t.Fatal("expected error when Protocol and Opcode are unset")
	}
}

func TestBuilder_DestNodeIDSetsFlags(t *testing.T) {
	frame, err := NewBuilder().
		Protocol(ProtocolInteractionModel).
		Opcode(OpcodeStatusReport).
		SourceNodeID(0x1).
		DestNodeID(0x2).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !frame.Header.Flags.SourcePresent() {
		t.Error("expected source-present bit")
	}
	if frame.Header.Flags.DSIZ() != MessageFlagDSIZUnicast {
		t.Errorf("DSIZ = %#x, want unicast", frame.Header.Flags.DSIZ())
	}
}

func TestBuilder_DestGroupIDSetsFlags(t *testing.T) {
	frame, err := NewBuilder().
		Protocol(ProtocolInteractionModel).
		Opcode(OpcodeStatusReport).
		DestGroupID(0xABCD).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if frame.Header.Flags.DSIZ() != MessageFlagDSIZGroup {
		t.Errorf("DSIZ = %#x, want group", frame.Header.Flags.DSIZ())
	}
	if frame.Header.DestNodeID != 0xABCD {
		t.Errorf("DestNodeID = %#x, want 0xABCD", frame.Header.DestNodeID)
	}
}

func TestBuilder_AckCounterSetsFlag(t *testing.T) {
	frame, err := NewBuilder().
		Protocol(ProtocolSecureChannel).
		Opcode(OpcodeMRPStandaloneAck).
		AckCounter(0x12345678).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !frame.PayloadHeader.ExchangeFlags.Has(ExchangeFlagAcknowledgement) {
		t.Error("expected acknowledgement bit")
	}
	if frame.PayloadHeader.AckCounter != 0x12345678 {
		t.Errorf("AckCounter = %#x", frame.PayloadHeader.AckCounter)
	}
}
