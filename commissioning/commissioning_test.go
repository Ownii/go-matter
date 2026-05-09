package commissioning

import (
	"bytes"
	"testing"

	"go-matter/message"
	"go-matter/tlv"
)

type loopMessenger struct {
	deliver func(*message.Frame) error
}

func (l *loopMessenger) SendMessage(f *message.Frame) error { return l.deliver(f) }

func TestPBKDFParamResponse_TLVRoundTrip(t *testing.T) {
	want := PBKDFParamResponse{
		InitiatorRandom:    bytes.Repeat([]byte{0xab}, 32),
		ResponderRandom:    bytes.Repeat([]byte{0xcd}, 32),
		ResponderSessionID: 0xBEEF,
		Params:             &PBKDFParamSet{Iterations: 1000, Salt: []byte("SPAKE2P Key Salt")},
	}
	encoded, err := tlv.Marshal(&want)
	if err != nil {
		t.Fatal(err)
	}
	var got PBKDFParamResponse
	if err := decodePayload(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.InitiatorRandom, want.InitiatorRandom) ||
		!bytes.Equal(got.ResponderRandom, want.ResponderRandom) ||
		got.ResponderSessionID != want.ResponderSessionID ||
		got.Params == nil ||
		got.Params.Iterations != want.Params.Iterations ||
		!bytes.Equal(got.Params.Salt, want.Params.Salt) {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}

	// Params must be omitted on the wire when nil.
	noParams := PBKDFParamResponse{InitiatorRandom: []byte{1}, ResponderRandom: []byte{2}, ResponderSessionID: 3}
	enc2, _ := tlv.Marshal(&noParams)
	var dec2 PBKDFParamResponse
	if err := decodePayload(enc2, &dec2); err != nil {
		t.Fatal(err)
	}
	if dec2.Params != nil {
		t.Errorf("expected Params omitted, got %+v", dec2.Params)
	}
}

func TestPBKDFParamRequestResponse_Loopback(t *testing.T) {
	const passcode = uint32(12345678)
	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000

	commissionee, err := NewCommissionee(passcode, salt, iterations)
	if err != nil {
		t.Fatal(err)
	}
	commissioner := NewCommissioner(nil)

	deviceMsg, controllerMsg := &loopMessenger{}, &loopMessenger{}
	commissionee.Messenger, commissioner.Messenger = deviceMsg, controllerMsg
	deviceMsg.deliver = commissioner.HandleMessage
	controllerMsg.deliver = commissionee.HandleMessage

	if err := commissioner.StartPASE(passcode); err != nil {
		t.Fatal(err)
	}

	if commissioner.State != StatePASE_Pake1 || commissionee.State != StatePASE_Pake1 {
		t.Errorf("states: commissioner=%d commissionee=%d, want Pake1=%d",
			commissioner.State, commissionee.State, StatePASE_Pake1)
	}
	if !bytes.Equal(commissioner.Salt, salt) || commissioner.Iterations != uint32(iterations) {
		t.Errorf("PBKDF params not propagated: salt=%x iter=%d", commissioner.Salt, commissioner.Iterations)
	}
	if !bytes.Equal(commissioner.ResponderRandom, commissionee.Random) ||
		commissioner.ResponderSessionID != commissionee.SessionID {
		t.Errorf("responder identity mismatch")
	}
	if !bytes.Equal(commissioner.Random, commissionee.InitiatorRandom) ||
		commissioner.SessionID != commissionee.InitiatorSessionID {
		t.Errorf("initiator identity mismatch")
	}
	if !bytes.Equal(commissioner.RequestPayload, commissionee.RequestPayload) ||
		!bytes.Equal(commissioner.ResponsePayload, commissionee.ResponsePayload) {
		t.Errorf("transcript mismatch")
	}
	if len(commissioner.RequestPayload) == 0 || len(commissioner.ResponsePayload) == 0 {
		t.Errorf("transcript empty")
	}
}

func TestCommissioner_HandleMessage_Errors(t *testing.T) {
	tests := []struct {
		name string
		resp PBKDFParamResponse
	}{
		{
			name: "wrong InitiatorRandom",
			resp: PBKDFParamResponse{
				InitiatorRandom:    bytes.Repeat([]byte{0x22}, 32),
				ResponderRandom:    bytes.Repeat([]byte{0x33}, 32),
				ResponderSessionID: 1,
				Params:             &PBKDFParamSet{Iterations: 1000, Salt: []byte("salt")},
			},
		},
		{
			name: "missing Params",
			resp: PBKDFParamResponse{
				InitiatorRandom:    bytes.Repeat([]byte{0x11}, 32),
				ResponderRandom:    bytes.Repeat([]byte{0x33}, 32),
				ResponderSessionID: 1,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCommissioner(nil)
			c.Random = bytes.Repeat([]byte{0x11}, 32)
			payload, _ := tlv.Marshal(&tc.resp)
			frame := &message.Frame{
				PayloadHeader: message.PayloadHeader{Opcode: message.OpcodePBKDFParamResponse},
				Payload:       payload,
			}
			if err := c.HandleMessage(frame); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
