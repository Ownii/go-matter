package crypto

import "errors"

// SessionKeyInfo is the HKDF info string used to derive the Matter PASE
// session keys from Ke (Matter Core Spec §4.13.2.1). The string also acts as
// the domain separator that keeps these keys distinct from any other use of
// the same shared secret.
const SessionKeyInfo = "SessionKeys"

// SessionKeyLength is the AES-128 key size mandated by Matter §5.3 for each
// of the three keys derived from Ke.
const SessionKeyLength = 16

// SessionKeys is the trio of 16-byte keys expanded from a PASE shared
// secret. I2RKey encrypts initiator → responder traffic, R2IKey encrypts
// the reverse, and AttestationChallenge is consumed by the operational
// credentials cluster during fabric provisioning.
type SessionKeys struct {
	I2RKey               []byte
	R2IKey               []byte
	AttestationChallenge []byte
}

// DeriveSessionKeysFromKe expands the PASE shared secret Ke into the three
// Matter session keys (Matter §4.13.2.1): one HKDF-SHA-256 call producing
// 48 bytes with empty salt and info = "SessionKeys", split into three
// 16-byte windows in (I2R, R2I, Attestation) order.
//
// TODO: cross-check the (empty-salt, "SessionKeys", 48-byte) parameter set
// against connectedhomeip/src/protocols/secure_channel/PASESession.cpp
// before treating the locked test vector in session_keys_test.go as
// spec-authoritative.
func DeriveSessionKeysFromKe(ke []byte) (SessionKeys, error) {
	if len(ke) == 0 {
		return SessionKeys{}, errors.New("crypto: Ke must be non-empty")
	}
	out, err := HKDF(ke, nil, []byte(SessionKeyInfo), 3*SessionKeyLength)
	if err != nil {
		return SessionKeys{}, err
	}
	return SessionKeys{
		I2RKey:               out[0:SessionKeyLength],
		R2IKey:               out[SessionKeyLength : 2*SessionKeyLength],
		AttestationChallenge: out[2*SessionKeyLength : 3*SessionKeyLength],
	}, nil
}
