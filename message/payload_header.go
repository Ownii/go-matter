package message

import (
	"encoding/binary"
	"errors"
)

// PayloadHeader is the Matter Protocol/Exchange Header (Matter Core Spec §4.4.3).
//
// On the wire (after any session decryption):
//
//	+------------------+----------------+
//	| Exchange Flags   |   1 byte       |
//	| Protocol Opcode  |   1 byte       |
//	| Exchange ID      |   2 bytes LE   |
//	| Protocol ID      |   2 bytes LE   |
//	| Vendor ID        |   2 bytes LE   | (if V flag set)
//	| Ack Counter      |   4 bytes LE   | (if A flag set)
//	+------------------+----------------+
type PayloadHeader struct {
	ExchangeFlags ExchangeFlags
	Opcode        Opcode
	ExchangeID    uint16
	ProtocolID    ProtocolID
	VendorID      uint16
	AckCounter    uint32
}

const payloadHeaderFixedSize = 1 + 1 + 2 + 2

var errPayloadHeaderTooShort = errors.New("message: payload header too short")

// Marshal encodes the payload header to its wire form.
func (p *PayloadHeader) Marshal() ([]byte, error) {
	size := payloadHeaderFixedSize
	if p.ExchangeFlags.Has(ExchangeFlagVendorPresent) {
		size += 2
	}
	if p.ExchangeFlags.Has(ExchangeFlagAcknowledgement) {
		size += 4
	}

	buf := make([]byte, size)
	buf[0] = byte(p.ExchangeFlags)
	buf[1] = byte(p.Opcode)
	binary.LittleEndian.PutUint16(buf[2:4], p.ExchangeID)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(p.ProtocolID))

	off := payloadHeaderFixedSize
	if p.ExchangeFlags.Has(ExchangeFlagVendorPresent) {
		binary.LittleEndian.PutUint16(buf[off:off+2], p.VendorID)
		off += 2
	}
	if p.ExchangeFlags.Has(ExchangeFlagAcknowledgement) {
		binary.LittleEndian.PutUint32(buf[off:off+4], p.AckCounter)
	}
	return buf, nil
}

// Unmarshal decodes a payload header from b and returns the number of bytes consumed.
func (p *PayloadHeader) Unmarshal(b []byte) (int, error) {
	if len(b) < payloadHeaderFixedSize {
		return 0, errPayloadHeaderTooShort
	}
	p.ExchangeFlags = ExchangeFlags(b[0])
	p.Opcode = Opcode(b[1])
	p.ExchangeID = binary.LittleEndian.Uint16(b[2:4])
	p.ProtocolID = ProtocolID(binary.LittleEndian.Uint16(b[4:6]))

	off := payloadHeaderFixedSize
	p.VendorID = 0
	p.AckCounter = 0

	if p.ExchangeFlags.Has(ExchangeFlagVendorPresent) {
		if len(b) < off+2 {
			return 0, errPayloadHeaderTooShort
		}
		p.VendorID = binary.LittleEndian.Uint16(b[off : off+2])
		off += 2
	}
	if p.ExchangeFlags.Has(ExchangeFlagAcknowledgement) {
		if len(b) < off+4 {
			return 0, errPayloadHeaderTooShort
		}
		p.AckCounter = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
	}
	return off, nil
}
