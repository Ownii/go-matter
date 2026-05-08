package message

// Frame is a fully decoded Matter message: the message header, the payload
// (exchange) header, and the application payload bytes.
//
// Phase 2 limitation: secured frames are not supported here. Once the session
// layer can decrypt, a Frame produced by Decode for a secured session will
// have an empty PayloadHeader/Payload until the session layer fills them.
//
// TODO: secured frames need session decrypt before payload header parsing.
type Frame struct {
	Header        Header
	PayloadHeader PayloadHeader
	Payload       []byte
}

// Encode serialises the frame to wire bytes.
func (f *Frame) Encode() ([]byte, error) {
	hdr, err := f.Header.Marshal()
	if err != nil {
		return nil, err
	}
	phdr, err := f.PayloadHeader.Marshal()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hdr)+len(phdr)+len(f.Payload))
	out = append(out, hdr...)
	out = append(out, phdr...)
	out = append(out, f.Payload...)
	return out, nil
}

// Decode parses a wire-format frame.
//
// For unsecured sessions (SessionID == 0 with SessionType == Unicast), the
// payload header is parsed inline. For secured sessions, decryption must
// happen first; this implementation currently treats the post-header bytes
// as the cleartext payload header + payload regardless, which is correct
// for the PASE handshake and breaks for encrypted traffic — see TODO above.
func Decode(b []byte) (*Frame, error) {
	var f Frame
	n, err := f.Header.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	m, err := f.PayloadHeader.Unmarshal(b[n:])
	if err != nil {
		return nil, err
	}
	tail := b[n+m:]
	if len(tail) > 0 {
		f.Payload = make([]byte, len(tail))
		copy(f.Payload, tail)
	}
	return &f, nil
}
