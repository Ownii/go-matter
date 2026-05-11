package crypto

import "errors"

// SessionKeyInfo is the HKDF info string used to derive the Matter PASE
// session keys from Ke (Matter Core Spec §4.13.2.1). The string also acts as
// the domain separator that keeps these keys distinct from any other use of
// the same shared secret.
const SessionKeyInfo = "SessionKeys"

// SessionKeys is the trio of 16-byte AES-128 keys expanded from a PASE
// shared secret. I2RKey encrypts initiator → responder traffic, R2IKey
// encrypts the reverse, and AttestationChallenge is consumed by the
// operational credentials cluster during fabric provisioning.
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
	out, err := HKDF(ke, nil, []byte(SessionKeyInfo), 48)
	if err != nil {
		return SessionKeys{}, err
	}
	return SessionKeys{
		I2RKey:               out[0:16],
		R2IKey:               out[16:32],
		AttestationChallenge: out[32:48],
	}, nil
}
