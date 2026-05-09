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
	StatePASE_PBKDFParamRequest
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

// PBKDFParamRequest is the first PASE message (Matter §4.13.1.1).
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

// PBKDFParamResponse is the second PASE message (Matter §4.13.1.2). The
// responder echoes InitiatorRandom to bind the transcript.
type PBKDFParamResponse struct {
	InitiatorRandom    []byte         `tlv:"1"`
	ResponderRandom    []byte         `tlv:"2"`
	ResponderSessionID uint16         `tlv:"3"`
	Params             *PBKDFParamSet `tlv:"4,omitempty"`
}

// Commissioner drives the PASE handshake from the controller side.
//
// SessionID is the initiator's chosen *future* secure session ID; the PASE
// frames themselves use unsecured session 0. RequestPayload / ResponsePayload
// retain the raw TLV bodies so Pake1 can build the SPAKE2+ context input
// (PBKDFParamRequest||PBKDFParamResponse, Matter §3.10).
type Commissioner struct {
	State          CommissioningState
	Messenger      CommissioningMessenger
	Passcode       uint32
	SpakeContext   *crypto.SPAKE2PProver
	Random         []byte
	SessionID      uint16
	ExchangeID     uint16
	MessageCounter uint32

	RequestPayload []byte

	ResponderRandom    []byte
	ResponderSessionID uint16
	Salt               []byte
	Iterations         uint32
	ResponsePayload    []byte
}

func NewCommissioner(messenger CommissioningMessenger) *Commissioner {
	return &Commissioner{State: StateIdle, Messenger: messenger}
}

func (c *Commissioner) StartPASE(passcode uint32) error {
	c.State = StatePASE_PBKDFParamRequest
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
	if err := bumpCounter(&c.MessageCounter); err != nil {
		return err
	}

	request := PBKDFParamRequest{
		InitiatorRandom:    c.Random,
		InitiatorSessionID: c.SessionID,
		HasPBKDFParameters: false,
	}

	frame, err := message.NewBuilder().
		Unsecured().
		MessageCounter(c.MessageCounter).
		Protocol(message.ProtocolSecureChannel).
		Opcode(message.OpcodePBKDFParamRequest).
		ExchangeID(c.ExchangeID).
		Initiator().
		RequestAck().
		Payload(&request).
		Build()
	if err != nil {
		return fmt.Errorf("commissioner: build PBKDFParamRequest: %w", err)
	}
	c.RequestPayload = frame.Payload

	if c.Messenger != nil {
		return c.Messenger.SendMessage(frame)
	}
	return nil
}

func (c *Commissioner) HandleMessage(frame *message.Frame) error {
	switch frame.PayloadHeader.Opcode {
	case message.OpcodePBKDFParamResponse:
		return c.handlePBKDFParamResponse(frame)
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
	c.State = StatePASE_Pake1
	return nil
}

// StartCASE is a stub. TODO: implement CASE Sigma1.
func (c *Commissioner) StartCASE(nodeID uint64) error {
	c.State = StateCASE
	return nil
}

// Commissionee drives the PASE handshake from the device side. (W0, L) is
// the persisted SPAKE2+ verifier — the device never stores the passcode
// itself. RequestPayload / ResponsePayload retain the raw TLV bodies for
// the Matter §3.10 transcript needed at Pake1.
type Commissionee struct {
	State        CommissioningState
	Salt         []byte
	Iterations   uint32
	W0           []byte
	L            []byte
	SpakeContext *crypto.SPAKE2PVerifier
	Random       []byte

	Messenger      CommissioningMessenger
	SessionID      uint16
	MessageCounter uint32

	InitiatorRandom    []byte
	InitiatorSessionID uint16
	InitiatorNodeID    uint64
	ExchangeID         uint16
	RequestPayload     []byte
	ResponsePayload    []byte
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
		// TODO: decode pA, run crypto.NewSPAKE2PVerifier(W0,L,ctx).ComputePB, send Pake2.
		c.State = StatePASE_Pake2
	case message.OpcodePASEPake3:
		// TODO: verify cA via SpakeContext.VerifyConfirmationA, seed session keys.
		c.State = StateComplete
	default:
		return fmt.Errorf("commissionee: unexpected opcode %#x in state %d",
			byte(frame.PayloadHeader.Opcode), c.State)
	}
	return nil
}

func (c *Commissionee) handlePBKDFParamRequest(frame *message.Frame) error {
	var req PBKDFParamRequest
	if err := decodePayload(frame.Payload, &req); err != nil {
		return fmt.Errorf("commissionee: decode PBKDFParamRequest: %w", err)
	}

	c.InitiatorRandom = req.InitiatorRandom
	c.InitiatorSessionID = req.InitiatorSessionID
	c.InitiatorNodeID = req.InitiatorNodeID
	c.ExchangeID = frame.PayloadHeader.ExchangeID
	c.RequestPayload = frame.Payload

	c.Random = make([]byte, 32)
	if _, err := rand.Read(c.Random); err != nil {
		return fmt.Errorf("commissionee: random: %w", err)
	}
	if c.SessionID == 0 {
		c.SessionID = 23456 // TODO: draw from SessionManager.
	}
	if err := bumpCounter(&c.MessageCounter); err != nil {
		return err
	}

	response := PBKDFParamResponse{
		InitiatorRandom:    c.InitiatorRandom,
		ResponderRandom:    c.Random,
		ResponderSessionID: c.SessionID,
	}
	if !req.HasPBKDFParameters {
		response.Params = &PBKDFParamSet{Iterations: c.Iterations, Salt: c.Salt}
	}

	out, err := message.NewBuilder().
		Unsecured().
		MessageCounter(c.MessageCounter).
		Protocol(message.ProtocolSecureChannel).
		Opcode(message.OpcodePBKDFParamResponse).
		ExchangeID(c.ExchangeID).
		AckCounter(frame.Header.MessageCounter).
		Payload(&response).
		Build()
	if err != nil {
		return fmt.Errorf("commissionee: build PBKDFParamResponse: %w", err)
	}

	c.ResponsePayload = out.Payload
	c.State = StatePASE_Pake1

	if c.Messenger != nil {
		return c.Messenger.SendMessage(out)
	}
	return nil
}

// decodePayload reads one top-level TLV element, recursively populating
// SubElements for containers, then reflects it into out.
func decodePayload(payload []byte, out interface{}) error {
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
