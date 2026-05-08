package message

// MessageFlags is the first byte of every Matter message frame.
// Layout (Matter Core Spec §4.4.1.1):
//
//	bit 7..4  Version (currently 0b0000)
//	bit 3     Reserved (must be 0)
//	bit 2     S — Source Node ID present
//	bit 1..0  DSIZ — Destination Node ID size:
//	            00 = absent
//	            01 = 64-bit unicast
//	            10 = 16-bit group
//	            11 = reserved
type MessageFlags uint8

const (
	MessageFlagSourceNodeIDPresent MessageFlags = 0x04

	MessageFlagDSIZMask     MessageFlags = 0x03
	MessageFlagDSIZAbsent   MessageFlags = 0x00
	MessageFlagDSIZUnicast  MessageFlags = 0x01
	MessageFlagDSIZGroup    MessageFlags = 0x02
	MessageFlagDSIZReserved MessageFlags = 0x03

	MessageVersionMask  MessageFlags = 0xF0
	MessageVersionShift              = 4
)

// SourcePresent reports whether the S bit is set.
func (f MessageFlags) SourcePresent() bool { return f&MessageFlagSourceNodeIDPresent != 0 }

// DSIZ extracts the destination size field.
func (f MessageFlags) DSIZ() MessageFlags { return f & MessageFlagDSIZMask }

// SecurityFlags is the byte that follows Session ID in the message header.
// Layout (Matter Core Spec §4.4.1.2):
//
//	bit 7    P — Privacy
//	bit 6    C — Control message
//	bit 5    MX — Message extensions present
//	bit 4..2 Reserved
//	bit 1..0 Session Type:
//	            00 = Unicast Session (unsecured or secured)
//	            01 = Group Session
//	            10..11 = Reserved
type SecurityFlags uint8

const (
	SecurityFlagPrivacy           SecurityFlags = 0x80
	SecurityFlagControl           SecurityFlags = 0x40
	SecurityFlagMessageExtensions SecurityFlags = 0x20

	SecurityFlagSessionTypeMask SecurityFlags = 0x03
	SessionTypeUnicast          SecurityFlags = 0x00
	SessionTypeGroup            SecurityFlags = 0x01
)

// SessionType extracts the session type bits.
func (f SecurityFlags) SessionType() SecurityFlags { return f & SecurityFlagSessionTypeMask }

// ExchangeFlags is the first byte of the payload (exchange) header.
// Layout (Matter Core Spec §4.4.3):
//
//	bit 7..5 Reserved
//	bit 4    V — Vendor ID present
//	bit 3    SX — Secured extensions present (reserved in current spec)
//	bit 2    R — Reliability requested (sender wants ack)
//	bit 1    A — Acknowledgement (this message acks a previous one)
//	bit 0    I — Initiator (this message comes from the exchange initiator)
type ExchangeFlags uint8

const (
	ExchangeFlagInitiator       ExchangeFlags = 0x01
	ExchangeFlagAcknowledgement ExchangeFlags = 0x02
	ExchangeFlagReliability     ExchangeFlags = 0x04
	ExchangeFlagSecuredExt      ExchangeFlags = 0x08
	ExchangeFlagVendorPresent   ExchangeFlags = 0x10
)

// Has reports whether all of mask's bits are set on f.
func (f ExchangeFlags) Has(mask ExchangeFlags) bool { return f&mask == mask }
