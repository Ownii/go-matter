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

// CommissioningState represents the current state of the commissioning process.
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

// CommissioningMessenger defines how to send commissioning frames.
type CommissioningMessenger interface {
	SendMessage(frame *message.Frame) error
}

// Commissioner (Initiator) handles the commissioning process from the controller side.
//
// Random is the InitiatorRandom drawn at StartPASE. SessionID is the
// initiator's chosen *future* secure session ID (echoed back to the responder
// in PBKDFParamRequest); the on-the-wire frame uses unsecured session 0
// during PASE, see message.Builder.Unsecured.
//
// RequestPayload / ResponsePayload capture the raw TLV bodies so the SPAKE2+
// context input — PBKDFParamRequest||PBKDFParamResponse per Matter §3.10 —
// can be reproduced when Pake1/2 land. Until then the response handler only
// validates parameter echo + parses (salt, iterations, ResponderRandom,
// ResponderSessionID).
type Commissioner struct {
	State          CommissioningState
	Messenger      CommissioningMessenger
	Passcode       uint32
	SpakeContext   *crypto.SPAKE2PProver
	Random         []byte
	SessionID      uint16
	ExchangeID     uint16
	MessageCounter uint32

	// Populated on StartPASE.
	RequestPayload []byte

	// Populated on receipt of PBKDFParamResponse.
	ResponderRandom    []byte
	ResponderSessionID uint16
	Salt               []byte
	Iterations         uint32
	ResponsePayload    []byte
}

// NewCommissioner creates a new Commissioner.
func NewCommissioner(messenger CommissioningMessenger) *Commissioner {
	return &Commissioner{
		State:     StateIdle,
		Messenger: messenger,
	}
}

// PBKDFParamRequest is the first message in PASE handshake.
type PBKDFParamRequest struct {
	InitiatorRandom    []byte `tlv:"1"`
	InitiatorSessionID uint16 `tlv:"2"`
	PasscodeID         uint16 `tlv:"3"`
	HasPBKDFParameters bool   `tlv:"4"`
	InitiatorNodeID    uint64 `tlv:"5,omitempty"`
}

// PBKDFParamSet carries the PBKDF parameters (salt + iteration count). The
// responder embeds it in PBKDFParamResponse only when the initiator did not
// already know the parameters (HasPBKDFParameters=false in the request).
type PBKDFParamSet struct {
	Iterations uint32 `tlv:"1"`
	Salt       []byte `tlv:"2"`
}

// PBKDFParamResponse is the second message in the PASE handshake. The
// responder echoes InitiatorRandom (transcript binding), supplies its own
// random + future secure session ID, and — if the initiator did not already
// know them — the PBKDF parameters.
type PBKDFParamResponse struct {
	InitiatorRandom    []byte         `tlv:"1"`
	ResponderRandom    []byte         `tlv:"2"`
	ResponderSessionID uint16         `tlv:"3"`
	Params             *PBKDFParamSet `tlv:"4,omitempty"`
}

// StartPASE initiates the PASE handshake by sending PBKDFParamRequest.
func (c *Commissioner) StartPASE(passcode uint32) error {
	c.State = StatePASE_PBKDFParamRequest
	c.Passcode = passcode

	// Generate random data for initiator
	c.Random = make([]byte, 32)
	if _, err := rand.Read(c.Random); err != nil {
		return err
	}

	if c.SessionID == 0 {
		// Assign a temporary Session ID if not set
		// In real impl, this comes from SessionManager
		c.SessionID = 12345
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
		PasscodeID:         0,
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
		return fmt.Errorf("failed to build PBKDFParamRequest frame: %w", err)
	}

	c.RequestPayload = append([]byte(nil), frame.Payload...)

	fmt.Printf("Sending PBKDFParamRequest: opcode=%#x exchange=%d payload=%x\n",
		byte(frame.PayloadHeader.Opcode), frame.PayloadHeader.ExchangeID, frame.Payload)
	if c.Messenger != nil {
		return c.Messenger.SendMessage(frame)
	}
	return nil
}

// HandleMessage processes responder-originated frames on the Commissioner. The
// only opcode handled today is PBKDFParamResponse; Pake2 will hang here next.
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
		// Initiator did not signal HasPBKDFParameters=true, so the responder
		// is required to supply Params here.
		return errors.New("commissioner: PBKDFParamResponse missing PBKDF parameters")
	}

	c.ResponderRandom = resp.ResponderRandom
	c.ResponderSessionID = resp.ResponderSessionID
	c.Salt = resp.Params.Salt
	c.Iterations = resp.Params.Iterations
	c.ResponsePayload = append([]byte(nil), frame.Payload...)
	c.State = StatePASE_Pake1
	return nil
}

// StartCASE initiates the CASE handshake.
func (c *Commissioner) StartCASE(nodeID uint64) error {
	c.State = StateCASE
	// TODO: Implement CASE initiator logic
	return nil
}

// Commissionee (Responder) handles the commissioning process from the device side.
//
// W0 and L are the persisted SPAKE2+ verifier (computed once at provisioning
// time via crypto.ComputeSPAKE2PVerifierData) — the device never stores the
// passcode itself. Salt and Iterations are echoed in PBKDFParamResponse so
// the Commissioner can re-run PBKDF2 with matching parameters.
//
// Random is the ResponderRandom drawn when PBKDFParamRequest arrives.
// SessionID is the responder's chosen *future* secure session ID, sent back
// to the initiator in PBKDFParamResponse.
//
// RequestPayload / ResponsePayload capture the raw TLV bodies for the
// transcript that the SPAKE2+ context input will need at Pake1.
type Commissionee struct {
	State        CommissioningState
	Passcode     uint32
	Salt         []byte
	Iterations   uint32
	W0           []byte
	L            []byte
	SpakeContext *crypto.SPAKE2PVerifier
	Random       []byte

	Messenger      CommissioningMessenger
	SessionID      uint16
	MessageCounter uint32

	// Populated when PBKDFParamRequest arrives.
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	InitiatorNodeID    uint64
	ExchangeID         uint16
	RequestPayload     []byte
	ResponsePayload    []byte
}

// NewCommissionee creates a new Commissionee. Passcode, salt, and iteration
// count are folded through PBKDF2 once at construction; only (W0, L) and the
// salt+iterations are kept thereafter.
func NewCommissionee(passcode uint32, salt []byte, iterations int) (*Commissionee, error) {
	w0, L, err := crypto.ComputeSPAKE2PVerifierData(passcode, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("commissionee: derive verifier: %w", err)
	}
	return &Commissionee{
		State:      StateIdle,
		Passcode:   passcode,
		Salt:       append([]byte(nil), salt...),
		Iterations: uint32(iterations),
		W0:         w0,
		L:          L,
	}, nil
}

// HandleMessage processes incoming commissioning frames. PBKDFParamRequest is
// fully implemented; Pake1/Pake3 are still scaffolds.
func (c *Commissionee) HandleMessage(frame *message.Frame) error {
	switch frame.PayloadHeader.Opcode {
	case message.OpcodePBKDFParamRequest:
		return c.handlePBKDFParamRequest(frame)
	case message.OpcodePASEPake1:
		// TODO: TLV-decode body to extract pA; build the PASE context bytes
		// (PBKDFParamRequest||Response transcript per Matter §3.10);
		// instantiate c.SpakeContext via crypto.NewSPAKE2PVerifier(c.W0,
		// c.L, ctx); call ComputePB(pA); send Pake2 carrying pB and cB.
		c.State = StatePASE_Pake2
	case message.OpcodePASEPake3:
		// TODO: TLV-decode body to extract cA; verify with
		// c.SpakeContext.VerifyConfirmationA(cA); on success transition
		// to StateComplete and seed the operational session keys from
		// SharedKey().
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
	c.RequestPayload = append([]byte(nil), frame.Payload...)

	c.Random = make([]byte, 32)
	if _, err := rand.Read(c.Random); err != nil {
		return fmt.Errorf("commissionee: random: %w", err)
	}

	if c.SessionID == 0 {
		// Real impl draws this from SessionManager; matches the
		// initiator-side default in StartPASE.
		c.SessionID = 23456
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
		response.Params = &PBKDFParamSet{
			Iterations: c.Iterations,
			Salt:       c.Salt,
		}
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

	c.ResponsePayload = append([]byte(nil), out.Payload...)
	c.State = StatePASE_Pake1

	if c.Messenger != nil {
		return c.Messenger.SendMessage(out)
	}
	return nil
}

// decodePayload parses a single top-level TLV element (recursively
// populating SubElements if it is a container) and decodes it into out.
func decodePayload(payload []byte, out interface{}) error {
	r := tlv.NewReader(bytes.NewReader(payload))
	elem, err := r.ReadElement()
	if err != nil {
		return err
	}
	if elem.Type == tlv.TypeStructure || elem.Type == tlv.TypeArray || elem.Type == tlv.TypeList {
		children, err := r.ReadContainerChildren()
		if err != nil {
			return err
		}
		elem.SubElements = children
	}
	return tlv.Decode(elem, out)
}

// bumpCounter bootstraps a message counter from 32 random bits the first
// time it is used (Matter §4.5.1.1) and increments it thereafter.
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
