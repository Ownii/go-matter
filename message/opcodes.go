package message

// ProtocolID identifies the Matter protocol that owns the payload.
// Matter Core Spec §4.4.3.1.
type ProtocolID uint16

const (
	ProtocolSecureChannel    ProtocolID = 0x0000
	ProtocolInteractionModel ProtocolID = 0x0001
	ProtocolBDX              ProtocolID = 0x0002
	ProtocolUserDirected     ProtocolID = 0x0003
)

// Opcode identifies a specific message within a protocol.
// Values below are for ProtocolSecureChannel (§4.10).
type Opcode uint8

const (
	OpcodeMRPStandaloneAck   Opcode = 0x10
	OpcodePBKDFParamRequest  Opcode = 0x20
	OpcodePBKDFParamResponse Opcode = 0x21
	OpcodePASEPake1          Opcode = 0x22
	OpcodePASEPake2          Opcode = 0x23
	OpcodePASEPake3          Opcode = 0x24
	OpcodeCASESigma1         Opcode = 0x30
	OpcodeCASESigma2         Opcode = 0x31
	OpcodeCASESigma3         Opcode = 0x32
	OpcodeCASESigma2Resume   Opcode = 0x33
	OpcodeStatusReport       Opcode = 0x40
)
