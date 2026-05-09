package commissioning

import (
	"bytes"
	"testing"

	"go-matter/message"
	"go-matter/tlv"
)

// loopMessenger forwards Frames synchronously to a peer's HandleMessage. It
// substitutes for the UDP transport in tests.
type loopMessenger struct {
	deliver func(*message.Frame) error
}

func (l *loopMessenger) SendMessage(f *message.Frame) error {
	if l.deliver == nil {
		return nil
	}
	return l.deliver(f)
}

func TestPBKDFParamResponse_TLVRoundTrip(t *testing.T) {
	want := PBKDFParamResponse{
		InitiatorRandom:    bytes.Repeat([]byte{0xab}, 32),
		ResponderRandom:    bytes.Repeat([]byte{0xcd}, 32),
		ResponderSessionID: 0xBEEF,
		Params: &PBKDFParamSet{
			Iterations: 1000,
			Salt:       []byte("SPAKE2P Key Salt"),
		},
	}

	encoded, err := tlv.Marshal(&want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got PBKDFParamResponse
	if err := decodePayload(encoded, &got); err != nil {
		t.Fatalf("decodePayload: %v", err)
	}

	if !bytes.Equal(got.InitiatorRandom, want.InitiatorRandom) {
		t.Errorf("InitiatorRandom mismatch")
	}
	if !bytes.Equal(got.ResponderRandom, want.ResponderRandom) {
		t.Errorf("ResponderRandom mismatch")
	}
	if got.ResponderSessionID != want.ResponderSessionID {
		t.Errorf("ResponderSessionID: got %d, want %d", got.ResponderSessionID, want.ResponderSessionID)
	}
	if got.Params == nil {
		t.Fatal("Params nil after round trip")
	}
	if got.Params.Iterations != want.Params.Iterations {
		t.Errorf("Iterations: got %d, want %d", got.Params.Iterations, want.Params.Iterations)
	}
	if !bytes.Equal(got.Params.Salt, want.Params.Salt) {
		t.Errorf("Salt mismatch")
	}
}

func TestPBKDFParamResponse_OmitsParamsWhenNil(t *testing.T) {
	resp := PBKDFParamResponse{
		InitiatorRandom:    []byte{1, 2, 3},
		ResponderRandom:    []byte{4, 5, 6},
		ResponderSessionID: 7,
		Params:             nil,
	}
	encoded, err := tlv.Marshal(&resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got PBKDFParamResponse
	if err := decodePayload(encoded, &got); err != nil {
		t.Fatalf("decodePayload: %v", err)
	}
	if got.Params != nil {
		t.Errorf("expected Params to be omitted, got %+v", got.Params)
	}
}

func TestPBKDFParamRequestResponse_Loopback(t *testing.T) {
	const passcode = uint32(12345678)
	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000

	commissionee, err := NewCommissionee(passcode, salt, iterations)
	if err != nil {
		t.Fatalf("NewCommissionee: %v", err)
	}
	commissioner := NewCommissioner(nil)

	deviceMsg := &loopMessenger{}
	controllerMsg := &loopMessenger{}
	commissionee.Messenger = deviceMsg
	commissioner.Messenger = controllerMsg

	deviceMsg.deliver = commissioner.HandleMessage
	controllerMsg.deliver = commissionee.HandleMessage

	if err := commissioner.StartPASE(passcode); err != nil {
		t.Fatalf("StartPASE: %v", err)
	}

	if commissioner.State != StatePASE_Pake1 {
		t.Errorf("commissioner.State = %d, want %d", commissioner.State, StatePASE_Pake1)
	}
	if commissionee.State != StatePASE_Pake1 {
		t.Errorf("commissionee.State = %d, want %d", commissionee.State, StatePASE_Pake1)
	}

	if !bytes.Equal(commissioner.Salt, salt) {
		t.Errorf("commissioner.Salt = %x, want %x", commissioner.Salt, salt)
	}
	if commissioner.Iterations != uint32(iterations) {
		t.Errorf("commissioner.Iterations = %d, want %d", commissioner.Iterations, iterations)
	}
	if !bytes.Equal(commissioner.ResponderRandom, commissionee.Random) {
		t.Errorf("commissioner.ResponderRandom != commissionee.Random")
	}
	if commissioner.ResponderSessionID != commissionee.SessionID {
		t.Errorf("ResponderSessionID mismatch: commissioner=%d commissionee=%d",
			commissioner.ResponderSessionID, commissionee.SessionID)
	}

	if !bytes.Equal(commissioner.Random, commissionee.InitiatorRandom) {
		t.Errorf("commissioner.Random != commissionee.InitiatorRandom")
	}
	if commissioner.SessionID != commissionee.InitiatorSessionID {
		t.Errorf("InitiatorSessionID mismatch: commissioner=%d commissionee=%d",
			commissioner.SessionID, commissionee.InitiatorSessionID)
	}

	if !bytes.Equal(commissioner.RequestPayload, commissionee.RequestPayload) {
		t.Errorf("RequestPayload transcript mismatch")
	}
	if !bytes.Equal(commissioner.ResponsePayload, commissionee.ResponsePayload) {
		t.Errorf("ResponsePayload transcript mismatch")
	}
	if len(commissioner.RequestPayload) == 0 || len(commissioner.ResponsePayload) == 0 {
		t.Errorf("transcript payloads empty: req=%d resp=%d",
			len(commissioner.RequestPayload), len(commissioner.ResponsePayload))
	}
}

func TestCommissioner_RejectsMismatchedInitiatorRandom(t *testing.T) {
	commissioner := NewCommissioner(nil)
	commissioner.Random = bytes.Repeat([]byte{0x11}, 32)

	resp := PBKDFParamResponse{
		InitiatorRandom:    bytes.Repeat([]byte{0x22}, 32), // wrong
		ResponderRandom:    bytes.Repeat([]byte{0x33}, 32),
		ResponderSessionID: 1,
		Params:             &PBKDFParamSet{Iterations: 1000, Salt: []byte("salt")},
	}
	encoded, err := tlv.Marshal(&resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	frame := &message.Frame{
		PayloadHeader: message.PayloadHeader{Opcode: message.OpcodePBKDFParamResponse},
		Payload:       encoded,
	}
	if err := commissioner.HandleMessage(frame); err == nil {
		t.Fatal("expected error for mismatched InitiatorRandom, got nil")
	}
}

func TestCommissioner_RejectsMissingParams(t *testing.T) {
	commissioner := NewCommissioner(nil)
	commissioner.Random = bytes.Repeat([]byte{0x11}, 32)

	resp := PBKDFParamResponse{
		InitiatorRandom:    commissioner.Random,
		ResponderRandom:    bytes.Repeat([]byte{0x33}, 32),
		ResponderSessionID: 1,
	}
	encoded, err := tlv.Marshal(&resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	frame := &message.Frame{
		PayloadHeader: message.PayloadHeader{Opcode: message.OpcodePBKDFParamResponse},
		Payload:       encoded,
	}
	if err := commissioner.HandleMessage(frame); err == nil {
		t.Fatal("expected error for missing PBKDF params, got nil")
	}
}
