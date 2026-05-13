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

type pasePeers struct {
	Commissioner   *Commissioner
	Commissionee   *Commissionee
	CommissionerSM *session.SessionManager
	CommissioneeSM *session.SessionManager
}

func setupPASEPeers(t *testing.T, devicePasscode, controllerPasscode uint32) (*pasePeers, error) {
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
	return &pasePeers{
		Commissioner:   commissioner,
		Commissionee:   commissionee,
		CommissionerSM: commissionerSM,
		CommissioneeSM: commissioneeSM,
	}, commissioner.StartPASE(controllerPasscode)
}

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

func TestPASE_Loopback(t *testing.T) {
	const passcode = uint32(12345678)
	peers, err := setupPASEPeers(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}
	commissioner, commissionee := peers.Commissioner, peers.Commissionee

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
	peers, err := setupPASEPeers(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	s, ok := peers.CommissionerSM.Session(peers.Commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session %d not installed", peers.Commissioner.SessionID)
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
	peers, err := setupPASEPeers(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	commSess, ok := peers.CommissionerSM.Session(peers.Commissioner.SessionID)
	if !ok {
		t.Fatalf("commissioner session not installed; commissionee mirroring check needs commissioner side present")
	}
	devSess, ok := peers.CommissioneeSM.Session(peers.Commissionee.SessionID)
	if !ok {
		t.Fatalf("commissionee session %d not installed", peers.Commissionee.SessionID)
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
	peers, err := setupPASEPeers(t, 12345678, 99999999)
	if err == nil {
		t.Fatal("expected handshake to fail with mismatched passcode, got nil error")
	}
	commissioner, commissionee := peers.Commissioner, peers.Commissionee
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
	peers, err := setupPASEPeers(t, passcode, passcode)
	if err != nil {
		t.Fatalf("PASE handshake: %v", err)
	}

	expectRoundtrip := func(label string, plaintext []byte,
		senderSM *session.SessionManager, senderID uint16,
		recipientSM *session.SessionManager, recipientID uint16,
	) {
		t.Helper()
		senderSess, _ := senderSM.Session(senderID)
		counter, err := senderSess.NextOutboundCounter()
		if err != nil {
			t.Fatalf("%s: NextOutboundCounter: %v", label, err)
		}
		// Frame's SessionID field carries the peer's chosen ID (so the
		// peer routes the frame to its own table entry on receipt).
		header := buildSecuredHeader(t, recipientID, counter)

		ct, err := senderSM.EncryptPayload(senderID, plaintext, header)
		if err != nil {
			t.Fatalf("%s: EncryptPayload: %v", label, err)
		}
		if bytes.Equal(ct, plaintext) {
			t.Fatalf("%s: ciphertext equals plaintext: AEAD did not run", label)
		}
		pt, err := recipientSM.DecryptPayload(recipientID, ct, header)
		if err != nil {
			t.Fatalf("%s: DecryptPayload: %v", label, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("%s: roundtrip mismatch: got %q want %q", label, pt, plaintext)
		}
	}

	expectRoundtrip("commissioner→commissionee", []byte("hello from commissioner"),
		peers.CommissionerSM, peers.Commissioner.SessionID,
		peers.CommissioneeSM, peers.Commissionee.SessionID)

	expectRoundtrip("commissionee→commissioner", []byte("hello back from commissionee"),
		peers.CommissioneeSM, peers.Commissionee.SessionID,
		peers.CommissionerSM, peers.Commissioner.SessionID)
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
