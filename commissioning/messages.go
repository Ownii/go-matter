package commissioning

// PASE wire-format types. Each struct's TLV layout matches the corresponding
// section of Matter §4.13.1.

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
