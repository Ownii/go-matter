package commissioning

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/tlv"
)

type CommissioningState int

const (
	StateIdle CommissioningState = iota
	StatePASE_PBKDFParamResponse
	StatePASE_Pake1
	StatePASE_Pake2
	StatePASE_Pake3
	StateCASE
	StateComplete
	StateError
)

type CommissioningMessenger interface {
	SendMessage(frame *message.Frame) error
}

// PBKDFParamRequest — Matter §4.13.1.1.
type PBKDFParamRequest struct {
	InitiatorRandom    []byte `tlv:"1"`
	InitiatorSessionID uint16 `tlv:"2"`
	PasscodeID         uint16 `tlv:"3"`
	HasPBKDFParameters bool   `tlv:"4"`
	InitiatorNodeID    uint64 `tlv:"5,omitempty"`
}

// PBKDFParamSet is sent inside PBKDFParamResponse only when the initiator
// did not already know the parameters.
type PBKDFParamSet struct {
	Iterations uint32 `tlv:"1"`
	Salt       []byte `tlv:"2"`
}

// PBKDFParamResponse — Matter §4.13.1.2. The responder echoes
// InitiatorRandom to bind the transcript.
type PBKDFParamResponse struct {
	InitiatorRandom    []byte         `tlv:"1"`
	ResponderRandom    []byte         `tlv:"2"`
	ResponderSessionID uint16         `tlv:"3"`
	Params             *PBKDFParamSet `tlv:"4,omitempty"`
}

// Pake1 — Matter §4.13.1.3.
type Pake1 struct {
	PA []byte `tlv:"1"`
}

// Pake2 — Matter §4.13.1.4.
type Pake2 struct {
	PB []byte `tlv:"1"`
	CB []byte `tlv:"2"`
}

// Pake3 — Matter §4.13.1.5.
type Pake3 struct {
	CA []byte `tlv:"1"`
}

const paseContextPrefix = "CHIP PAKE V1 Commissioning"

// paseContext returns the raw SPAKE2+ context bytes
// (prefix || PBKDFParamRequest || PBKDFParamResponse) per Matter §3.10.
// crypto.spakeFinalize hashes it internally, so it is passed un-hashed.
func paseContext(req, resp []byte) []byte {
	out := make([]byte, 0, len(paseContextPrefix)+len(req)+len(resp))
	out = append(out, paseContextPrefix...)
	out = append(out, req...)
	out = append(out, resp...)
	return out
}

// Commissioner drives the PASE handshake from the controller (initiator) side.
//
// SessionID is the initiator's chosen *future* secure session ID; the PASE
// frames themselves use unsecured session 0.
type Commissioner struct {
	State          CommissioningState
	Messenger      CommissioningMessenger
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

func NewCommissioner(messenger CommissioningMessenger) *Commissioner {
	return &Commissioner{State: StateIdle, Messenger: messenger}
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

// Commissionee drives the PASE handshake from the device (responder) side.
// (W0, L) is the persisted SPAKE2+ verifier — the device never stores the
// passcode itself.
type Commissionee struct {
	State        CommissioningState
	Salt         []byte
	Iterations   uint32
	W0           []byte
	L            []byte
	Random       []byte

	Messenger      CommissioningMessenger
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

func NewCommissionee(passcode uint32, salt []byte, iterations int) (*Commissionee, error) {
	w0, L, err := crypto.ComputeSPAKE2PVerifierData(passcode, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("commissionee: derive verifier: %w", err)
	}
	return &Commissionee{
		State:      StateIdle,
		Salt:       append([]byte(nil), salt...),
		Iterations: uint32(iterations),
		W0:         w0,
		L:          L,
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

// decodePayload reads one top-level TLV element, recursively populating
// SubElements for containers, then reflects it into out.
func decodePayload(payload []byte, out any) error {
	r := tlv.NewReader(bytes.NewReader(payload))
	elem, err := r.ReadElement()
	if err != nil {
		return err
	}
	switch elem.Type {
	case tlv.TypeStructure, tlv.TypeArray, tlv.TypeList:
		children, err := r.ReadContainerChildren()
		if err != nil {
			return err
		}
		elem.SubElements = children
	}
	return tlv.Decode(elem, out)
}

// bumpCounter seeds *ctr from 32 random bits on first use (Matter §4.5.1.1)
// and increments thereafter.
func bumpCounter(ctr *uint32) error {
	if *ctr == 0 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		*ctr = binary.LittleEndian.Uint32(b[:])
		return nil
	}
	*ctr++
	return nil
}
