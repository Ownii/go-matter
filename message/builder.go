package message

import (
	"errors"
	"fmt"
	"go-matter/tlv"
)

// Builder constructs a Frame fluently.
//
// Usage:
//
//	frame, err := message.NewBuilder().
//	    Unsecured().
//	    MessageCounter(ctr).
//	    Protocol(message.ProtocolSecureChannel).
//	    Opcode(message.OpcodePBKDFParamRequest).
//	    ExchangeID(1).
//	    Initiator().
//	    RequestAck().
//	    Payload(&request).
//	    Build()
//
// Errors are accumulated; the first error is returned from Build().
type Builder struct {
	frame      Frame
	hasPayload bool
	err        error
}

// NewBuilder returns a fresh frame builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// SessionID sets the session identifier on the message header.
func (b *Builder) SessionID(id uint16) *Builder {
	b.frame.Header.SessionID = id
	return b
}

// MessageCounter sets the message counter on the message header.
func (b *Builder) MessageCounter(c uint32) *Builder {
	b.frame.Header.MessageCounter = c
	return b
}

// SourceNodeID sets the source node ID and flips the S bit.
func (b *Builder) SourceNodeID(id uint64) *Builder {
	b.frame.Header.SourceNodeID = id
	b.frame.Header.Flags |= MessageFlagSourceNodeIDPresent
	return b
}

// DestNodeID sets a 64-bit unicast destination node ID.
func (b *Builder) DestNodeID(id uint64) *Builder {
	b.frame.Header.DestNodeID = id
	b.frame.Header.Flags = (b.frame.Header.Flags &^ MessageFlagDSIZMask) | MessageFlagDSIZUnicast
	return b
}

// DestGroupID sets a 16-bit group destination ID.
func (b *Builder) DestGroupID(id uint16) *Builder {
	b.frame.Header.DestNodeID = uint64(id)
	b.frame.Header.Flags = (b.frame.Header.Flags &^ MessageFlagDSIZMask) | MessageFlagDSIZGroup
	return b
}

// Unsecured marks the frame as belonging to the unsecured session
// (SessionID 0, SessionType Unicast). Used for the PASE handshake.
func (b *Builder) Unsecured() *Builder {
	b.frame.Header.SessionID = 0
	b.frame.Header.SecurityFlags = (b.frame.Header.SecurityFlags &^ SecurityFlagSessionTypeMask) | SessionTypeUnicast
	return b
}

// Protocol sets the protocol ID on the payload header.
func (b *Builder) Protocol(id ProtocolID) *Builder {
	b.frame.PayloadHeader.ProtocolID = id
	return b
}

// Opcode sets the protocol opcode on the payload header.
func (b *Builder) Opcode(op Opcode) *Builder {
	b.frame.PayloadHeader.Opcode = op
	return b
}

// ExchangeID sets the exchange identifier on the payload header.
func (b *Builder) ExchangeID(id uint16) *Builder {
	b.frame.PayloadHeader.ExchangeID = id
	return b
}

// Initiator marks this message as coming from the exchange initiator.
func (b *Builder) Initiator() *Builder {
	b.frame.PayloadHeader.ExchangeFlags |= ExchangeFlagInitiator
	return b
}

// RequestAck flips the Reliability bit, asking the peer to acknowledge.
func (b *Builder) RequestAck() *Builder {
	b.frame.PayloadHeader.ExchangeFlags |= ExchangeFlagReliability
	return b
}

// AckCounter records the counter being acknowledged and sets the A bit.
func (b *Builder) AckCounter(c uint32) *Builder {
	b.frame.PayloadHeader.AckCounter = c
	b.frame.PayloadHeader.ExchangeFlags |= ExchangeFlagAcknowledgement
	return b
}

// Vendor records a vendor ID on the payload header and sets the V bit.
func (b *Builder) Vendor(id uint16) *Builder {
	b.frame.PayloadHeader.VendorID = id
	b.frame.PayloadHeader.ExchangeFlags |= ExchangeFlagVendorPresent
	return b
}

// Payload sets the application payload. Accepted forms:
//   - nil: no payload
//   - []byte: used as-is (already-encoded passthrough)
//   - any other value: encoded via tlv.Marshal
func (b *Builder) Payload(v any) *Builder {
	b.hasPayload = true
	if v == nil {
		b.frame.Payload = nil
		return b
	}
	if raw, ok := v.([]byte); ok {
		b.frame.Payload = raw
		return b
	}
	encoded, err := tlv.Marshal(v)
	if err != nil {
		if b.err == nil {
			b.err = fmt.Errorf("message: payload marshal: %w", err)
		}
		return b
	}
	b.frame.Payload = encoded
	return b
}

// Build returns the assembled frame, validating required fields.
func (b *Builder) Build() (*Frame, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.frame.PayloadHeader.ProtocolID == 0 && b.frame.PayloadHeader.Opcode == 0 {
		// Both at their zero value strongly suggests the caller forgot to
		// set them — Secure Channel + opcode 0 is "MsgCounterSyncReq", which
		// is not what an empty builder represents.
		return nil, errors.New("message: builder missing Protocol/Opcode")
	}
	out := b.frame
	return &out, nil
}
