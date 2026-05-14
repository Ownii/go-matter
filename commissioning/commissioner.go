package commissioning

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/session"
)

// Commissioner drives the PASE handshake from the controller (initiator) side.
//
// SessionID is the initiator's chosen *future* secure session ID; the PASE
// frames themselves use unsecured session 0.
type Commissioner struct {
	State          CommissioningState
	Messenger      CommissioningMessenger
	sessionManager *session.SessionManager
	Passcode       uint32
	Random         []byte
	SessionID      uint16
	ExchangeID     uint16
	MessageCounter uint32

	RequestPayload  []byte
	ResponsePayload []byte

	ResponderRandom    []byte
	ResponderSessionID uint16
	Salt               []byte
	Iterations         uint32

	Ke []byte // 16-byte shared key, populated after Pake2 verification

	prover *crypto.SPAKE2PProver
}

// NewCommissioner constructs a Commissioner. sm must not be nil — PASE
// produces a secure session which is installed in sm after Pake2; passing
// nil panics immediately rather than nil-derefing mid-handshake.
func NewCommissioner(messenger CommissioningMessenger, sm *session.SessionManager) *Commissioner {
	if sm == nil {
		panic("commissioning: NewCommissioner requires a non-nil SessionManager")
	}
	return &Commissioner{State: StateIdle, Messenger: messenger, sessionManager: sm}
}

func (c *Commissioner) StartPASE(passcode uint32) error {
	c.Passcode = passcode

	c.Random = make([]byte, 32)
	if _, err := rand.Read(c.Random); err != nil {
		return err
	}
	if c.SessionID == 0 {
		c.SessionID = 12345 // TODO: draw from SessionManager.
	}
	if c.ExchangeID == 0 {
		c.ExchangeID = 1
	}

	frame, err := c.buildFrame(message.OpcodePBKDFParamRequest, 0, &PBKDFParamRequest{
		InitiatorRandom:    c.Random,
		InitiatorSessionID: c.SessionID,
	})
	if err != nil {
		return err
	}
	c.RequestPayload = frame.Payload
	c.State = StatePASE_PBKDFParamResponse
	return c.send(frame)
}

func (c *Commissioner) HandleMessage(frame *message.Frame) error {
	switch frame.PayloadHeader.Opcode {
	case message.OpcodePBKDFParamResponse:
		return c.handlePBKDFParamResponse(frame)
	case message.OpcodePASEPake2:
		return c.handlePake2(frame)
	default:
		return fmt.Errorf("commissioner: unexpected opcode %#x in state %d",
			byte(frame.PayloadHeader.Opcode), c.State)
	}
}

func (c *Commissioner) handlePBKDFParamResponse(frame *message.Frame) error {
	var resp PBKDFParamResponse
	if err := decodePayload(frame.Payload, &resp); err != nil {
		return fmt.Errorf("commissioner: decode PBKDFParamResponse: %w", err)
	}
	if !bytes.Equal(resp.InitiatorRandom, c.Random) {
		return errors.New("commissioner: PBKDFParamResponse echoed wrong InitiatorRandom")
	}
	if resp.Params == nil {
		return errors.New("commissioner: PBKDFParamResponse missing PBKDF parameters")
	}

	c.ResponderRandom = resp.ResponderRandom
	c.ResponderSessionID = resp.ResponderSessionID
	c.Salt = resp.Params.Salt
	c.Iterations = resp.Params.Iterations
	c.ResponsePayload = frame.Payload

	return c.sendPake1(frame.Header.MessageCounter)
}

func (c *Commissioner) sendPake1(ackMC uint32) error {
	w0, w1, err := crypto.Spake2pW0W1FromPasscode(c.Passcode, c.Salt, int(c.Iterations))
	if err != nil {
		return fmt.Errorf("commissioner: derive w0/w1: %w", err)
	}
	c.prover, err = crypto.NewSPAKE2PProver(w0, w1, paseContext(c.RequestPayload, c.ResponsePayload))
	if err != nil {
		return fmt.Errorf("commissioner: new prover: %w", err)
	}
	pA, err := c.prover.ComputePA()
	if err != nil {
		return fmt.Errorf("commissioner: ComputePA: %w", err)
	}

	frame, err := c.buildFrame(message.OpcodePASEPake1, ackMC, &Pake1{PA: pA})
	if err != nil {
		return err
	}
	c.State = StatePASE_Pake2
	return c.send(frame)
}

func (c *Commissioner) handlePake2(frame *message.Frame) error {
	if c.prover == nil {
		return errors.New("commissioner: Pake2 received before Pake1 sent")
	}
	var p2 Pake2
	if err := decodePayload(frame.Payload, &p2); err != nil {
		return fmt.Errorf("commissioner: decode Pake2: %w", err)
	}
	if err := c.prover.Finalize(p2.PB); err != nil {
		return fmt.Errorf("commissioner: SPAKE2+ finalize: %w", err)
	}
	if err := c.prover.VerifyConfirmationB(p2.CB); err != nil {
		return fmt.Errorf("commissioner: verify cB: %w", err)
	}
	cA, err := c.prover.ConfirmationA()
	if err != nil {
		return err
	}
	if c.Ke, err = c.prover.SharedKey(); err != nil {
		return err
	}

	if err := installPASESession(c.sessionManager, c.SessionID, c.Ke, session.RoleInitiator); err != nil {
		return fmt.Errorf("commissioner: %w", err)
	}

	out, err := c.buildFrame(message.OpcodePASEPake3, frame.Header.MessageCounter, &Pake3{CA: cA})
	if err != nil {
		return err
	}
	c.State = StateComplete
	return c.send(out)
}

// StartCASE is a stub. TODO: implement CASE Sigma1.
func (c *Commissioner) StartCASE(nodeID uint64) error {
	c.State = StateCASE
	return nil
}

// buildFrame assembles an outgoing initiator-side PASE frame: bumps the
// message counter, sets the standard unsecured/SecureChannel/Initiator/R
// flags, and piggybacks an Ack when ackMC != 0.
func (c *Commissioner) buildFrame(opcode message.Opcode, ackMC uint32, payload any) (*message.Frame, error) {
	if err := bumpCounter(&c.MessageCounter); err != nil {
		return nil, err
	}
	b := message.NewBuilder().
		Unsecured().
		Protocol(message.ProtocolSecureChannel).
		Opcode(opcode).
		ExchangeID(c.ExchangeID).
		MessageCounter(c.MessageCounter).
		Initiator().
		RequestAck().
		Payload(payload)
	if ackMC != 0 {
		b = b.AckCounter(ackMC)
	}
	frame, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("commissioner: build opcode=%#x: %w", byte(opcode), err)
	}
	return frame, nil
}

func (c *Commissioner) send(frame *message.Frame) error {
	if c.Messenger == nil {
		return nil
	}
	return c.Messenger.SendMessage(frame)
}
