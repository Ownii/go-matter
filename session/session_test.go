package session

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"go-matter/crypto"
	"go-matter/message"
)

// pairedSessions installs two SessionManagers that share the same PASE-derived
// keys but with opposite roles, so an initiator-side encrypt round-trips
// through the responder-side decrypt.
func pairedSessions(t *testing.T) (initSM, respSM *SessionManager, sessionID uint16, initNode, respNode uint64, keys crypto.SessionKeys) {
	t.Helper()
	// A fake 16-byte Ke; the bytes themselves don't matter for the round
	// trip — only that both sides derive the same SessionKeys from it.
	ke := bytes.Repeat([]byte{0xA5}, 16)
	var err error
	keys, err = crypto.DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("DeriveSessionKeysFromKe: %v", err)
	}
	sessionID = 0x1234
	initNode = 0x1111111111111111
	respNode = 0x2222222222222222
	initSM = NewSessionManager(nil)
	respSM = NewSessionManager(nil)
	initSM.InstallSecureSession(sessionID, initNode, respNode, keys, RoleInitiator)
	respSM.InstallSecureSession(sessionID, respNode, initNode, keys, RoleResponder)
	return
}

// buildHeader marshals a minimal unicast secured-frame header carrying the
// given message counter and source node ID. The bytes are both AAD and the
// nonce input on the receiver side.
func buildHeader(t *testing.T, sessionID uint16, counter uint32, srcNode uint64) []byte {
	t.Helper()
	h := message.Header{
		Flags:          message.MessageFlagSourceNodeIDPresent,
		SessionID:      sessionID,
		SecurityFlags:  message.SessionTypeUnicast,
		MessageCounter: counter,
		SourceNodeID:   srcNode,
	}
	b, err := h.Marshal()
	if err != nil {
		t.Fatalf("Header.Marshal: %v", err)
	}
	return b
}

func TestRoundTrip_InitiatorToResponder(t *testing.T) {
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)

	plaintext := []byte("hello matter")
	initSess, _ := initSM.Session(sid)
	counter, err := initSess.NextOutboundCounter()
	if err != nil {
		t.Fatalf("NextOutboundCounter: %v", err)
	}
	if counter != 1 {
		t.Fatalf("expected first counter 1, got %d", counter)
	}
	header := buildHeader(t, sid, counter, initNode)

	ct, err := initSM.EncryptPayload(sid, plaintext, header)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatalf("ciphertext equals plaintext: encryption did not happen")
	}

	pt, err := respSM.DecryptPayload(sid, ct, header)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %x want %x", pt, plaintext)
	}
}

func TestRoundTrip_ResponderToInitiator(t *testing.T) {
	initSM, respSM, sid, _, respNode, _ := pairedSessions(t)

	plaintext := []byte("ack from device")
	respSess, _ := respSM.Session(sid)
	counter, err := respSess.NextOutboundCounter()
	if err != nil {
		t.Fatalf("NextOutboundCounter: %v", err)
	}
	header := buildHeader(t, sid, counter, respNode)

	ct, err := respSM.EncryptPayload(sid, plaintext, header)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}

	pt, err := initSM.DecryptPayload(sid, ct, header)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip mismatch: got %x want %x", pt, plaintext)
	}
}

// TestDirection_WrongKeyRejects sets up a session where both sides have the
// *same* role. The receiver's DecryptKey is then I2RKey while the sender also
// encrypted with I2RKey, so AEAD auth must fail — proving that role mismatch
// shows up as a hard error rather than silent garbage.
func TestDirection_WrongKeyRejects(t *testing.T) {
	ke := bytes.Repeat([]byte{0xA5}, 16)
	keys, err := crypto.DeriveSessionKeysFromKe(ke)
	if err != nil {
		t.Fatalf("DeriveSessionKeysFromKe: %v", err)
	}
	const sid uint16 = 0x4321
	initNode := uint64(0x1111111111111111)
	respNode := uint64(0x2222222222222222)
	a := NewSessionManager(nil)
	b := NewSessionManager(nil)
	a.InstallSecureSession(sid, initNode, respNode, keys, RoleInitiator)
	b.InstallSecureSession(sid, respNode, initNode, keys, RoleInitiator) // intentional

	aSess, _ := a.Session(sid)
	counter, _ := aSess.NextOutboundCounter()
	header := buildHeader(t, sid, counter, initNode)
	ct, err := a.EncryptPayload(sid, []byte("payload"), header)
	if err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if _, err := b.DecryptPayload(sid, ct, header); err == nil {
		t.Fatalf("expected decrypt failure when both sides hold the same role")
	}
}

func TestReplayWindow_RejectsDuplicate(t *testing.T) {
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)
	initSess, _ := initSM.Session(sid)

	for i := 1; i <= 3; i++ {
		counter, _ := initSess.NextOutboundCounter()
		header := buildHeader(t, sid, counter, initNode)
		ct, err := initSM.EncryptPayload(sid, []byte("msg"), header)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		if _, err := respSM.DecryptPayload(sid, ct, header); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}

	// Replay of counter=2: re-encrypt under the same nonce. EncryptPayload
	// is stateless w.r.t. the counter (it reads it from the header), so
	// rebuilding a frame for an already-delivered counter just produces a
	// valid replay candidate.
	replayHeader := buildHeader(t, sid, 2, initNode)
	replayCT, err := initSM.EncryptPayload(sid, []byte("msg"), replayHeader)
	if err != nil {
		t.Fatalf("re-encrypt for replay: %v", err)
	}
	if _, err := respSM.DecryptPayload(sid, replayCT, replayHeader); !errors.Is(err, ErrReplayedMessageCounter) {
		t.Fatalf("expected ErrReplayedMessageCounter for replay of counter=2, got %v", err)
	}
}

func TestReplayWindow_AcceptsOutOfOrderWithinWindow(t *testing.T) {
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)

	// Deliver counters in order 1, 5, 3, 4 — 3 and 4 are within-window
	// new arrivals after 5 set the max.
	deliver := func(counter uint32) error {
		header := buildHeader(t, sid, counter, initNode)
		ct, err := initSM.EncryptPayload(sid, []byte("x"), header)
		if err != nil {
			return err
		}
		_, err = respSM.DecryptPayload(sid, ct, header)
		return err
	}

	for _, c := range []uint32{1, 5, 3, 4} {
		if err := deliver(c); err != nil {
			t.Fatalf("deliver counter=%d: %v", c, err)
		}
	}

	// A second arrival of counter=3 must now be rejected (bit is set).
	if err := deliver(3); !errors.Is(err, ErrReplayedMessageCounter) {
		t.Fatalf("expected replay rejection for counter=3 redelivery, got %v", err)
	}
}

func TestReplayWindow_RejectsBeforeWindow(t *testing.T) {
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)

	// Jump max to 100, then try counter=60 (more than 32 below max).
	for _, c := range []uint32{1, 100} {
		header := buildHeader(t, sid, c, initNode)
		ct, _ := initSM.EncryptPayload(sid, []byte("x"), header)
		if _, err := respSM.DecryptPayload(sid, ct, header); err != nil {
			t.Fatalf("deliver counter=%d: %v", c, err)
		}
	}

	header := buildHeader(t, sid, 60, initNode)
	ct, _ := initSM.EncryptPayload(sid, []byte("x"), header)
	_, err := respSM.DecryptPayload(sid, ct, header)
	if !errors.Is(err, ErrReplayedMessageCounter) {
		t.Fatalf("expected before-window rejection for counter=60 after max=100, got %v", err)
	}
}

// TestReplayWindow_AuthFailDoesNotAdvance ensures that a tampered ciphertext
// (which AEAD will reject) does NOT mutate the window. Otherwise an attacker
// could open a gap that a later replay would fall into.
func TestReplayWindow_AuthFailDoesNotAdvance(t *testing.T) {
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)
	initSess, _ := initSM.Session(sid)

	// Deliver counter=1 honestly.
	counter, _ := initSess.NextOutboundCounter()
	header := buildHeader(t, sid, counter, initNode)
	ct, _ := initSM.EncryptPayload(sid, []byte("ok"), header)
	if _, err := respSM.DecryptPayload(sid, ct, header); err != nil {
		t.Fatalf("legit deliver: %v", err)
	}

	// Forge a header with counter=100 but valid-looking bytes, and a junk
	// ciphertext. AEAD must fail; the window must not advance to 100.
	tamperedHeader := buildHeader(t, sid, 100, initNode)
	junk := bytes.Repeat([]byte{0xFF}, 32)
	if _, err := respSM.DecryptPayload(sid, junk, tamperedHeader); err == nil {
		t.Fatalf("expected AEAD failure on tampered frame")
	}

	// Now deliver an honest counter=2. If the window had advanced to 100,
	// counter=2 would be before-window and rejected — but it should pass.
	counter, _ = initSess.NextOutboundCounter()
	if counter != 2 {
		t.Fatalf("expected next counter 2, got %d", counter)
	}
	header2 := buildHeader(t, sid, counter, initNode)
	ct2, _ := initSM.EncryptPayload(sid, []byte("ok2"), header2)
	if _, err := respSM.DecryptPayload(sid, ct2, header2); err != nil {
		t.Fatalf("post-tamper legit deliver should succeed: %v", err)
	}
}

func TestUnsecuredSession_PassThrough(t *testing.T) {
	sm := NewSessionManager(nil)
	payload := []byte("clear handshake")
	header := buildHeader(t, UnsecuredSessionID, 1, 0)

	out, err := sm.EncryptPayload(UnsecuredSessionID, payload, header)
	if err != nil {
		t.Fatalf("Encrypt on session 0: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("session 0 encrypt must pass through; got %x want %x", out, payload)
	}

	out2, err := sm.DecryptPayload(UnsecuredSessionID, payload, header)
	if err != nil {
		t.Fatalf("Decrypt on session 0: %v", err)
	}
	if !bytes.Equal(out2, payload) {
		t.Fatalf("session 0 decrypt must pass through; got %x want %x", out2, payload)
	}
}

func TestEncryptPayload_UnknownSession(t *testing.T) {
	sm := NewSessionManager(nil)
	header := buildHeader(t, 42, 1, 0)
	_, err := sm.EncryptPayload(42, []byte("x"), header)
	if !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("expected ErrUnknownSession, got %v", err)
	}
	_, err = sm.DecryptPayload(42, []byte("x"), header)
	if !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("expected ErrUnknownSession, got %v", err)
	}
}

func TestNextOutboundCounter_Exhaustion(t *testing.T) {
	sm := NewSessionManager(nil)
	keys, _ := crypto.DeriveSessionKeysFromKe(bytes.Repeat([]byte{1}, 16))
	s := sm.InstallSecureSession(7, 1, 2, keys, RoleInitiator)
	s.OutCounter = math.MaxUint32

	if _, err := s.NextOutboundCounter(); !errors.Is(err, crypto.ErrCounterExhausted) {
		t.Fatalf("expected ErrCounterExhausted, got %v", err)
	}
	if s.OutCounter != math.MaxUint32 {
		t.Fatalf("exhausted counter must not advance, got %d", s.OutCounter)
	}
}

func TestReplayWindow_LargeJumpClearsBitmap(t *testing.T) {
	// A jump > 32 should leave the bitmap empty (all old in-window slots
	// fall off the left edge). The next jump-back-into-window counter
	// must be accepted.
	initSM, respSM, sid, initNode, _, _ := pairedSessions(t)

	// Accept 5, then jump to 100. The window now covers 69..100.
	for _, c := range []uint32{5, 100} {
		header := buildHeader(t, sid, c, initNode)
		ct, _ := initSM.EncryptPayload(sid, []byte("x"), header)
		if _, err := respSM.DecryptPayload(sid, ct, header); err != nil {
			t.Fatalf("deliver counter=%d: %v", c, err)
		}
	}

	// 80 is within window (100-80=20 ≤ 32) and has never been seen.
	header := buildHeader(t, sid, 80, initNode)
	ct, _ := initSM.EncryptPayload(sid, []byte("x"), header)
	if _, err := respSM.DecryptPayload(sid, ct, header); err != nil {
		t.Fatalf("counter=80 within window should be accepted: %v", err)
	}
}
