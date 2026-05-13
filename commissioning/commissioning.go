// Package commissioning implements the Matter PASE handshake (Matter §4.13).
// Commissioner is the controller (initiator) side; Commissionee is the device
// (responder) side. Wire-format types live in messages.go.
package commissioning

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/session"
	"go-matter/tlv"
)

type CommissioningState int

const (
	StateIdle CommissioningState = iota
	StatePASE_PBKDFParamResponse
	StatePASE_Pake1
	StatePASE_Pake2
	StatePASE_Pake3
	StateCASE
	StateComplete
	StateError
)

type CommissioningMessenger interface {
	SendMessage(frame *message.Frame) error
}

const paseContextPrefix = "CHIP PAKE V1 Commissioning"

// paseContext returns the raw SPAKE2+ context bytes
// (prefix || PBKDFParamRequest || PBKDFParamResponse) per Matter §3.10.
// crypto.spakeFinalize hashes it internally, so it is passed un-hashed.
func paseContext(req, resp []byte) []byte {
	out := make([]byte, 0, len(paseContextPrefix)+len(req)+len(resp))
	out = append(out, paseContextPrefix...)
	out = append(out, req...)
	out = append(out, resp...)
	return out
}

// decodePayload reads one top-level TLV element, recursively populating
// SubElements for containers, then reflects it into out.
func decodePayload(payload []byte, out any) error {
	r := tlv.NewReader(bytes.NewReader(payload))
	elem, err := r.ReadElement()
	if err != nil {
		return err
	}
	switch elem.Type {
	case tlv.TypeStructure, tlv.TypeArray, tlv.TypeList:
		children, err := r.ReadContainerChildren()
		if err != nil {
			return err
		}
		elem.SubElements = children
	}
	return tlv.Decode(elem, out)
}

// bumpCounter seeds *ctr from 32 random bits on first use (Matter §4.5.1.1)
// and increments thereafter.
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

// installPASESession derives the AES-CCM session keys from Ke
// (Matter §4.13.2.1) and registers them in sm under id with role.
// Called by both PASE handlers once SharedKey() has succeeded.
func installPASESession(sm *session.SessionManager, id uint16, ke []byte, role session.Role) error {
	keys, err := crypto.DeriveSessionKeysFromKe(ke)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}
	sm.InstallSecureSession(id, session.UnspecifiedNodeID, session.UnspecifiedNodeID, keys, role)
	return nil
}
