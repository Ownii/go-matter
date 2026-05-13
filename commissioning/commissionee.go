package commissioning

import (
	"crypto/rand"
	"errors"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/session"
)

// Commissionee drives the PASE handshake from the device (responder) side.
// (W0, L) is the persisted SPAKE2+ verifier — the device never stores the
// passcode itself.
type Commissionee struct {
	State      CommissioningState
	Salt       []byte
	Iterations uint32
	W0         []byte
	L          []byte
	Random     []byte

	Messenger      CommissioningMessenger
	SessionManager *session.SessionManager
	SessionID      uint16
	MessageCounter uint32

	InitiatorRandom    []byte
	InitiatorSessionID uint16
	ExchangeID         uint16
	RequestPayload     []byte
	ResponsePayload    []byte

	Ke []byte // 16-byte shared key, populated after Pake3 verification

	verifier *crypto.SPAKE2PVerifier
}

func NewCommissionee(passcode uint32, salt []byte, iterations int, sm *session.SessionManager) (*Commissionee, error) {
	if sm == nil {
		return nil, errors.New("commissionee: session manager must not be nil")
	}
	w0, L, err := crypto.ComputeSPAKE2PVerifierData(passcode, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("commissionee: derive verifier: %w", err)
	}
	return &Commissionee{
		State:          StateIdle,
		SessionManager: sm,
		Salt:           append([]byte(nil), salt...),
		Iterations:     uint32(iterations),
		W0:             w0,
		L:              L,
	}, nil
}

func (c *Commissionee) HandleMessage(frame *message.Frame) error {
	switch frame.PayloadHeader.Opcode {
	case message.OpcodePBKDFParamRequest:
		return c.handlePBKDFParamRequest(frame)
	case message.OpcodePASEPake1:
		return c.handlePake1(frame)
	case message.OpcodePASEPake3:
		return c.handlePake3(frame)
	default:
		return fmt.Errorf("commissionee: unexpected opcode %#x in state %d",
			byte(frame.PayloadHeader.Opcode), c.State)
	}
}

func (c *Commissionee) handlePBKDFParamRequest(frame *message.Frame) error {
	var req PBKDFParamRequest
	if err := decodePayload(frame.Payload, &req); err != nil {
		return fmt.Errorf("commissionee: decode PBKDFParamRequest: %w", err)
	}

	c.InitiatorRandom = req.InitiatorRandom
	c.InitiatorSessionID = req.InitiatorSessionID
	c.ExchangeID = frame.PayloadHeader.ExchangeID
	c.RequestPayload = frame.Payload

	c.Random = make([]byte, 32)
	if _, err := rand.Read(c.Random); err != nil {
		return fmt.Errorf("commissionee: random: %w", err)
	}
	if c.SessionID == 0 {
		c.SessionID = 23456 // TODO: draw from SessionManager.
	}

	resp := PBKDFParamResponse{
		InitiatorRandom:    c.InitiatorRandom,
		ResponderRandom:    c.Random,
		ResponderSessionID: c.SessionID,
	}
	if !req.HasPBKDFParameters {
		resp.Params = &PBKDFParamSet{Iterations: c.Iterations, Salt: c.Salt}
	}

	out, err := c.buildFrame(message.OpcodePBKDFParamResponse, frame.Header.MessageCounter, &resp)
	if err != nil {
		return err
	}
	c.ResponsePayload = out.Payload
	c.State = StatePASE_Pake1
	return c.send(out)
}

func (c *Commissionee) handlePake1(frame *message.Frame) error {
	var p1 Pake1
	if err := decodePayload(frame.Payload, &p1); err != nil {
		return fmt.Errorf("commissionee: decode Pake1: %w", err)
	}
	verifier, err := crypto.NewSPAKE2PVerifier(c.W0, c.L, paseContext(c.RequestPayload, c.ResponsePayload))
	if err != nil {
		return fmt.Errorf("commissionee: new verifier: %w", err)
	}
	pB, err := verifier.ComputePB(p1.PA)
	if err != nil {
		return fmt.Errorf("commissionee: ComputePB: %w", err)
	}
	if err := verifier.Finalize(); err != nil {
		return fmt.Errorf("commissionee: SPAKE2+ finalize: %w", err)
	}
	cB, err := verifier.ConfirmationB()
	if err != nil {
		return err
	}
	c.verifier = verifier

	out, err := c.buildFrame(message.OpcodePASEPake2, frame.Header.MessageCounter, &Pake2{PB: pB, CB: cB})
	if err != nil {
		return err
	}
	c.State = StatePASE_Pake3
	return c.send(out)
}

func (c *Commissionee) handlePake3(frame *message.Frame) error {
	if c.verifier == nil {
		return errors.New("commissionee: Pake3 received before Pake1")
	}
	var p3 Pake3
	if err := decodePayload(frame.Payload, &p3); err != nil {
		return fmt.Errorf("commissionee: decode Pake3: %w", err)
	}
	if err := c.verifier.VerifyConfirmationA(p3.CA); err != nil {
		return fmt.Errorf("commissionee: verify cA: %w", err)
	}
	ke, err := c.verifier.SharedKey()
	if err != nil {
		return err
	}
	c.Ke = ke
	c.State = StateComplete
	return nil
}

// buildFrame assembles an outgoing responder-side PASE frame: bumps the
// message counter, sets the standard unsecured/SecureChannel/R flags, and
// piggybacks an Ack when ackMC != 0.
func (c *Commissionee) buildFrame(opcode message.Opcode, ackMC uint32, payload any) (*message.Frame, error) {
	if err := bumpCounter(&c.MessageCounter); err != nil {
		return nil, err
	}
	b := message.NewBuilder().
		Unsecured().
		Protocol(message.ProtocolSecureChannel).
		Opcode(opcode).
		ExchangeID(c.ExchangeID).
		MessageCounter(c.MessageCounter).
		RequestAck().
		Payload(payload)
	if ackMC != 0 {
		b = b.AckCounter(ackMC)
	}
	frame, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("commissionee: build opcode=%#x: %w", byte(opcode), err)
	}
	return frame, nil
}

func (c *Commissionee) send(frame *message.Frame) error {
	if c.Messenger == nil {
		return nil
	}
	return c.Messenger.SendMessage(frame)
}
