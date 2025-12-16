package commissioning

import (
	"crypto/rand"
	"fmt"
	"go-matter/crypto"
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

// CommissioningMessenger defines how to send commissioning messages.
type CommissioningMessenger interface {
	SendMessage(payload []byte) error
}

// Commissioner (Initiator) handles the commissioning process from the controller side.
type Commissioner struct {
	State        CommissioningState
	Messenger    CommissioningMessenger
	Passcode     uint32
	SpakeContext *crypto.SPAKE2PContext
	Random       []byte
	SessionID    uint16
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

	// Construct PBKDFParamRequest
	request := PBKDFParamRequest{
		InitiatorRandom:    c.Random,
		InitiatorSessionID: c.SessionID,
		PasscodeID:         0,
		HasPBKDFParameters: false,
	}

	payload, err := tlv.Marshal(&request)
	if err != nil {
		return fmt.Errorf("failed to marshal PBKDFParamRequest: %w", err)
	}

	fmt.Printf("Sending PBKDFParamRequest: %x\n", payload)
	if c.Messenger != nil {
		return c.Messenger.SendMessage(payload)
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

// HandleMessage processes incoming commissioning messages.
func (c *Commissionee) HandleMessage(payload []byte) error {
	// TODO: Parse message using tlv.Reader
	// Switch c.State
	// Perform transition
	return nil
}
