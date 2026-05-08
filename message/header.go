package message

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Header is the Matter Message Header (Matter Core Spec §4.4.1).
//
// On the wire, the layout is:
//
//	+----------------+----------------+
//	| Message Flags  |    1 byte      |
//	| Session ID     |    2 bytes LE  |
//	| Security Flags |    1 byte      |
//	| Msg Counter    |    4 bytes LE  |
//	| Source Node ID |    8 bytes LE  | (only if S bit set)
//	| Dest Node ID   |    0/2/8 bytes | (per DSIZ)
//	+----------------+----------------+
//
// Variable-width fields are driven by Flags; callers should set Flags before
// calling Marshal so the encoded layout matches the populated fields.
type Header struct {
	Flags          MessageFlags
	SessionID      uint16
	SecurityFlags  SecurityFlags
	MessageCounter uint32
	SourceNodeID   uint64
	DestNodeID     uint64
}

const headerFixedSize = 1 + 2 + 1 + 4

var (
	errHeaderTooShort       = errors.New("message: header too short")
	errHeaderReservedDSIZ   = errors.New("message: reserved DSIZ value 0b11")
	errHeaderUnknownVersion = errors.New("message: unsupported message format version")
)

// Marshal encodes the header to its wire form.
func (h *Header) Marshal() ([]byte, error) {
	size := headerFixedSize
	if h.Flags.SourcePresent() {
		size += 8
	}
	switch h.Flags.DSIZ() {
	case MessageFlagDSIZAbsent:
	case MessageFlagDSIZUnicast:
		size += 8
	case MessageFlagDSIZGroup:
		size += 2
	default:
		return nil, errHeaderReservedDSIZ
	}

	buf := make([]byte, size)
	buf[0] = byte(h.Flags)
	binary.LittleEndian.PutUint16(buf[1:3], h.SessionID)
	buf[3] = byte(h.SecurityFlags)
	binary.LittleEndian.PutUint32(buf[4:8], h.MessageCounter)

	off := headerFixedSize
	if h.Flags.SourcePresent() {
		binary.LittleEndian.PutUint64(buf[off:off+8], h.SourceNodeID)
		off += 8
	}
	switch h.Flags.DSIZ() {
	case MessageFlagDSIZUnicast:
		binary.LittleEndian.PutUint64(buf[off:off+8], h.DestNodeID)
	case MessageFlagDSIZGroup:
		binary.LittleEndian.PutUint16(buf[off:off+2], uint16(h.DestNodeID))
	}
	return buf, nil
}

// Unmarshal decodes a header from b and returns the number of bytes consumed.
func (h *Header) Unmarshal(b []byte) (int, error) {
	if len(b) < headerFixedSize {
		return 0, errHeaderTooShort
	}
	h.Flags = MessageFlags(b[0])
	if h.Flags&MessageVersionMask != 0 {
		return 0, fmt.Errorf("%w: 0x%X", errHeaderUnknownVersion, byte(h.Flags&MessageVersionMask)>>MessageVersionShift)
	}
	h.SessionID = binary.LittleEndian.Uint16(b[1:3])
	h.SecurityFlags = SecurityFlags(b[3])
	h.MessageCounter = binary.LittleEndian.Uint32(b[4:8])

	off := headerFixedSize
	h.SourceNodeID = 0
	h.DestNodeID = 0

	if h.Flags.SourcePresent() {
		if len(b) < off+8 {
			return 0, errHeaderTooShort
		}
		h.SourceNodeID = binary.LittleEndian.Uint64(b[off : off+8])
		off += 8
	}
	switch h.Flags.DSIZ() {
	case MessageFlagDSIZAbsent:
	case MessageFlagDSIZUnicast:
		if len(b) < off+8 {
			return 0, errHeaderTooShort
		}
		h.DestNodeID = binary.LittleEndian.Uint64(b[off : off+8])
		off += 8
	case MessageFlagDSIZGroup:
		if len(b) < off+2 {
			return 0, errHeaderTooShort
		}
		h.DestNodeID = uint64(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
	default:
		return 0, errHeaderReservedDSIZ
	}
	return off, nil
}
