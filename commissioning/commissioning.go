package commissioning

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
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
type Commissioner struct {
	State          CommissioningState
	Messenger      CommissioningMessenger
	Passcode       uint32
	SpakeContext   *crypto.SPAKE2PContext
	Random         []byte
	SessionID      uint16
	ExchangeID     uint16
	MessageCounter uint32
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
	// Bootstrap message counter from a 32-bit random value (Matter §4.5.1.1)
	// rather than starting at 0, so collisions across restarts are unlikely.
	if c.MessageCounter == 0 {
		var ctr [4]byte
		if _, err := rand.Read(ctr[:]); err != nil {
			return err
		}
		c.MessageCounter = binary.LittleEndian.Uint32(ctr[:])
	} else {
		c.MessageCounter++
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

	fmt.Printf("Sending PBKDFParamRequest: opcode=%#x exchange=%d payload=%x\n",
		byte(frame.PayloadHeader.Opcode), frame.PayloadHeader.ExchangeID, frame.Payload)
	if c.Messenger != nil {
		return c.Messenger.SendMessage(frame)
	}
	return nil
}

// StartCASE initiates the CASE handshake.
func (c *Commissioner) StartCASE(nodeID uint64) error {
	c.State = StateCASE
	// TODO: Implement CASE initiator logic
	return nil
}

// Commissionee (Responder) handles the commissioning process from the device side.
type Commissionee struct {
	State        CommissioningState
	Passcode     uint32
	SpakeContext *crypto.SPAKE2PContext
	Random       []byte
}

// NewCommissionee creates a new Commissionee.
func NewCommissionee(passcode uint32) *Commissionee {
	return &Commissionee{
		State:    StateIdle,
		Passcode: passcode,
	}
}

// HandleMessage processes incoming commissioning frames.
func (c *Commissionee) HandleMessage(frame *message.Frame) error {
	// TODO: dispatch on c.State and frame.PayloadHeader.Opcode for Pake1/Pake2/Pake3.
	// For now just record the opcode of the most recent message so the sample
	// can show that decoding worked end to end.
	_ = frame
	return nil
}
