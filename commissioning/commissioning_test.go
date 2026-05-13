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

func TestPASE_InstallsSecureSession_Commissioner(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, _, commissionerSM, _, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	s, ok := commissionerSM.Session(commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session %d not installed", commissioner.SessionID)
	}
	if s.LocalNodeID != session.UnspecifiedNodeID || s.PeerNodeID != session.UnspecifiedNodeID {
		t.Errorf("PASE NodeIDs must be UnspecifiedNodeID, got local=%d peer=%d", s.LocalNodeID, s.PeerNodeID)
	}
	if len(s.EncryptKey) != 16 || len(s.DecryptKey) != 16 || len(s.AttestationChallenge) != 16 {
		t.Errorf("expected three 16-byte keys, got encrypt=%d decrypt=%d attestation=%d",
			len(s.EncryptKey), len(s.DecryptKey), len(s.AttestationChallenge))
	}
}

func TestPASE_InstallsSecureSession_Commissionee(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, commissionerSM, commissioneeSM, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	commSess, ok := commissionerSM.Session(commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session not installed (Task 3 precondition)")
	}
	devSess, ok := commissioneeSM.Session(commissionee.SessionID)
	if !ok {
		t.Fatalf("commissionee session %d not installed", commissionee.SessionID)
	}

	if devSess.LocalNodeID != session.UnspecifiedNodeID || devSess.PeerNodeID != session.UnspecifiedNodeID {
		t.Errorf("PASE NodeIDs must be UnspecifiedNodeID, got local=%d peer=%d", devSess.LocalNodeID, devSess.PeerNodeID)
	}

	if !bytes.Equal(commSess.EncryptKey, devSess.DecryptKey) {
		t.Errorf("commissioner EncryptKey must mirror commissionee DecryptKey (I2R): %x vs %x",
			commSess.EncryptKey, devSess.DecryptKey)
	}
	if !bytes.Equal(commSess.DecryptKey, devSess.EncryptKey) {
		t.Errorf("commissioner DecryptKey must mirror commissionee EncryptKey (R2I): %x vs %x",
			commSess.DecryptKey, devSess.EncryptKey)
	}
	if !bytes.Equal(commSess.AttestationChallenge, devSess.AttestationChallenge) {
		t.Errorf("AttestationChallenge must match across peers: %x vs %x",
			commSess.AttestationChallenge, devSess.AttestationChallenge)
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

// buildSecuredHeader produces the wire bytes of a minimal unicast
// secured-frame header. The bytes act both as AEAD AAD and as the input
// from which both peers reconstruct the AES-CCM nonce. For PASE-secure
// sessions the S-flag is not set, so SourceNodeID is implicit zero on
// the wire (matching connectedhomeip's secure-session send path).
func buildSecuredHeader(t *testing.T, destSessionID uint16, counter uint32) []byte {
	t.Helper()
	h := message.Header{
		SessionID:      destSessionID,
		SecurityFlags:  message.SessionTypeUnicast,
		MessageCounter: counter,
	}
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("Header.Marshal: %v", err)
	}
	return b
}

func TestPASE_CrossEncryptRoundtrip(t *testing.T) {
	const passcode = uint32(12345678)
	commissioner, commissionee, commissionerSM, commissioneeSM, err := pasePair(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	// Commissioner → Commissionee.
	{
		plaintext := []byte("hello from commissioner")
		commSess, _ := commissionerSM.Session(commissioner.SessionID)
		counter, err := commSess.NextOutboundCounter()
		if err != nil {
			t.Fatalf("commissioner NextOutboundCounter: %v", err)
		}
		// Frame's SessionID field carries the peer's chosen ID (so the
		// peer routes the frame to its own table entry on receipt).
		header := buildSecuredHeader(t, commissionee.SessionID, counter)

		ct, err := commissionerSM.EncryptPayload(commissioner.SessionID, plaintext, header)
		if err != nil {
			t.Fatalf("commissioner EncryptPayload: %v", err)
		}
		if bytes.Equal(ct, plaintext) {
			t.Fatalf("ciphertext equals plaintext: AEAD did not run")
		}
		pt, err := commissioneeSM.DecryptPayload(commissionee.SessionID, ct, header)
		if err != nil {
			t.Fatalf("commissionee DecryptPayload (forward): %v", err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("forward roundtrip mismatch: got %q want %q", pt, plaintext)
		}
	}

	// Commissionee → Commissioner.
	{
		plaintext := []byte("hello back from commissionee")
		devSess, _ := commissioneeSM.Session(commissionee.SessionID)
		counter, err := devSess.NextOutboundCounter()
		if err != nil {
			t.Fatalf("commissionee NextOutboundCounter: %v", err)
		}
		header := buildSecuredHeader(t, commissioner.SessionID, counter)

		ct, err := commissioneeSM.EncryptPayload(commissionee.SessionID, plaintext, header)
		if err != nil {
			t.Fatalf("commissionee EncryptPayload: %v", err)
		}
		pt, err := commissionerSM.DecryptPayload(commissioner.SessionID, ct, header)
		if err != nil {
			t.Fatalf("commissioner DecryptPayload (reverse): %v", err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("reverse roundtrip mismatch: got %q want %q", pt, plaintext)
		}
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
