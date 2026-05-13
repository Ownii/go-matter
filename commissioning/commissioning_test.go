package commissioning

import (
	"bytes"
	"testing"

	"go-matter/message"
	"go-matter/session"
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

func pasePair(t *testing.T, devicePasscode, controllerPasscode uint32) (
	*Commissioner, *Commissionee, *session.SessionManager, *session.SessionManager, error,
) {
	t.Helper()
	salt := []byte("SPAKE2P Key Salt")
	const iterations = 1000
	commissionerSM := session.NewSessionManager(nil)
	commissioneeSM := session.NewSessionManager(nil)
	commissionee, err := NewCommissionee(devicePasscode, salt, iterations, commissioneeSM)
	if err != nil {
		t.Fatal(err)
	}
	commissioner := NewCommissioner(nil, commissionerSM)
	deviceMsg, controllerMsg := &loopMessenger{}, &loopMessenger{}
	commissionee.Messenger, commissioner.Messenger = deviceMsg, controllerMsg
	deviceMsg.deliver = commissioner.HandleMessage
	controllerMsg.deliver = commissionee.HandleMessage
	return commissioner, commissionee, commissionerSM, commissioneeSM, commissioner.StartPASE(controllerPasscode)
}

func TestPASE_Loopback(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, _, _, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	if commissioner.State != StateComplete || commissionee.State != StateComplete {
		t.Errorf("states: commissioner=%d commissionee=%d, want Complete=%d",
			commissioner.State, commissionee.State, StateComplete)
	}
	if len(commissioner.Ke) != 16 || !bytes.Equal(commissioner.Ke, commissionee.Ke) {
		t.Errorf("Ke mismatch or wrong length: commissioner=%x commissionee=%x",
			commissioner.Ke, commissionee.Ke)
	}
	if !bytes.Equal(commissioner.ResponderRandom, commissionee.Random) ||
		commissioner.ResponderSessionID != commissionee.SessionID ||
		!bytes.Equal(commissioner.Random, commissionee.InitiatorRandom) ||
		commissioner.SessionID != commissionee.InitiatorSessionID {
		t.Errorf("identity propagation mismatch")
	}
	if !bytes.Equal(commissioner.RequestPayload, commissionee.RequestPayload) ||
		!bytes.Equal(commissioner.ResponsePayload, commissionee.ResponsePayload) {
		t.Errorf("transcript mismatch")
	}
}

func TestPASE_WrongPasscode(t *testing.T) {
	commissioner, commissionee, _, _, err := pasePair(t, 12345678, 99999999)
	if err == nil {
		t.Fatal("expected handshake to fail with mismatched passcode, got nil error")
	}
	if commissioner.State == StateComplete || commissionee.State == StateComplete {
		t.Errorf("states should not reach Complete on bad passcode: commissioner=%d commissionee=%d",
			commissioner.State, commissionee.State)
	}
	if commissioner.Ke != nil || commissionee.Ke != nil {
		t.Errorf("Ke must remain unset on bad passcode")
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
			c := NewCommissioner(nil, session.NewSessionManager(nil))
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
