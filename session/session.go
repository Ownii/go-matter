// Package session owns Matter's encryption boundary: per-direction
// AES-128-CCM keys derived from PASE/CASE, the outbound message counter,
// and the inbound replay window (Matter §4.5; see
// docs/Messaging_Architecture.md). Session ID 0 is the unsecured-channel
// sentinel and is pass-through on both encrypt and decrypt.
package session

import (
	"errors"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/transport"
)

// UnsecuredSessionID carries the PASE/CASE handshake itself; no entry
// exists in the session table for it.
const UnsecuredSessionID uint16 = 0

// UnspecifiedNodeID is the value used for both local and peer Node IDs
// when installing a PASE-secure session. PASE runs before fabric
// provisioning, so neither side has an operational Node ID yet; the
// reference implementation (connectedhomeip's SecureSessionTable.cpp)
// explicitly rejects any other value for kPASE sessions. The zero is
// also what flows into the AES-CCM nonce on the secure-session send
// path (connectedhomeip SessionManager.cpp:286-289).
const UnspecifiedNodeID uint64 = 0

// MessageCounterWindowSize is the unicast-secured replay window per Matter
// §4.5.4.2 (matches CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE).
const MessageCounterWindowSize uint32 = 32

var (
	ErrUnknownSession         = errors.New("session: unknown session id")
	ErrReplayedMessageCounter = errors.New("session: replayed message counter")
)

// PayloadHandler is the upcall the session layer uses to deliver
// decrypted bodies without depending on the protocol packages.
type PayloadHandler interface {
	HandlePayload(sessionID uint16, payload []byte) error
}

type Role int

const (
	RoleInitiator Role = iota
	RoleResponder
)

// Session is the crypto context for one secure peer-to-peer link.
// Not to be confused with the "Secure Channel" *protocol* (ProtocolID
// 0x0000, see message/opcodes.go) — that protocol's opcodes ride inside
// a Session's encrypted payload.
//
// Unicast only; group sessions (Matter §4.5.4.2 group rules,
// MSG_COUNTER_SYNC_REQ) are out of scope until TODO §17-18.
type Session struct {
	ID                   uint16
	LocalNodeID          uint64
	PeerNodeID           uint64
	EncryptKey           []byte // local → peer
	DecryptKey           []byte // peer → local
	AttestationChallenge []byte
	OutCounter           uint32
	replay               replayWindow
}

// NextOutboundCounter advances and returns the counter the caller will
// stamp into the next message header. Returns crypto.ErrCounterExhausted
// before the counter would wrap; the keys must then be retired
// (Matter §4.5.1.1).
func (s *Session) NextOutboundCounter() (uint32, error) {
	if s.OutCounter == ^uint32(0) {
		return 0, crypto.ErrCounterExhausted
	}
	s.OutCounter++
	return s.OutCounter, nil
}

// SessionManager is not safe for concurrent use; the exchange manager
// (TODO §18) will serialise access per session once it lands.
type SessionManager struct {
	sessions map[uint16]*Session
	handler  PayloadHandler
	provider crypto.CryptoProvider
}

func NewSessionManager(handler PayloadHandler) *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
		handler:  handler,
		provider: &crypto.DefaultCryptoProvider{},
	}
}

// InstallSecureSession registers keys derived from a completed PASE or
// CASE handshake. The role argument picks which of (I2RKey, R2IKey) is
// the local encrypt key once, so the hot path never re-branches on it.
func (sm *SessionManager) InstallSecureSession(
	id uint16,
	localNodeID, peerNodeID uint64,
	keys crypto.SessionKeys,
	role Role,
) *Session {
	s := &Session{
		ID:                   id,
		LocalNodeID:          localNodeID,
		PeerNodeID:           peerNodeID,
		AttestationChallenge: keys.AttestationChallenge,
	}
	if role == RoleInitiator {
		s.EncryptKey, s.DecryptKey = keys.I2RKey, keys.R2IKey
	} else {
		s.EncryptKey, s.DecryptKey = keys.R2IKey, keys.I2RKey
	}
	sm.sessions[id] = s
	return s
}

func (sm *SessionManager) Session(id uint16) (*Session, bool) {
	s, ok := sm.sessions[id]
	return s, ok
}

// EncryptPayload seals payload with AES-128-CCM. The header bytes must
// already carry the outbound counter (via Session.NextOutboundCounter)
// and become the AEAD's AAD: Matter authenticates the cleartext header
// even though it isn't encrypted (§4.5.3).
func (sm *SessionManager) EncryptPayload(sessionID uint16, payload []byte, header []byte) ([]byte, error) {
	if sessionID == UnsecuredSessionID {
		return payload, nil
	}
	s, ok := sm.sessions[sessionID]
	if !ok {
		return nil, ErrUnknownSession
	}
	var h message.Header
	if _, err := h.Unmarshal(header); err != nil {
		return nil, fmt.Errorf("session: parse outbound header: %w", err)
	}
	nonce := crypto.BuildNonce(byte(h.SecurityFlags), h.MessageCounter, h.SourceNodeID)
	return sm.provider.Encrypt(s.EncryptKey, nonce, payload, header)
}

// DecryptPayload opens an AES-128-CCM ciphertext. The replay-window
// commit is deferred until AEAD auth succeeds — otherwise a tampered
// frame could advance the window and open a gap an attacker would later
// fill (§4.5.4.2).
func (sm *SessionManager) DecryptPayload(sessionID uint16, ciphertext []byte, header []byte) ([]byte, error) {
	if sessionID == UnsecuredSessionID {
		return ciphertext, nil
	}
	s, ok := sm.sessions[sessionID]
	if !ok {
		return nil, ErrUnknownSession
	}
	var h message.Header
	if _, err := h.Unmarshal(header); err != nil {
		return nil, fmt.Errorf("session: parse inbound header: %w", err)
	}
	commit, err := s.replay.check(h.MessageCounter)
	if err != nil {
		return nil, err
	}
	nonce := crypto.BuildNonce(byte(h.SecurityFlags), h.MessageCounter, h.SourceNodeID)
	plaintext, err := sm.provider.Decrypt(s.DecryptKey, nonce, ciphertext, header)
	if err != nil {
		return nil, err
	}
	commit()
	return plaintext, nil
}

// replayWindow is a sliding bitmap of the last MessageCounterWindowSize
// accepted counters. Unicast counters never wrap (Matter §4.5.1.1;
// senders retire the session before 2^32-1 via
// crypto.ErrCounterExhausted), so plain unsigned comparison is enough —
// the §4.5.4.2 mod-2^32 rules collapse to three branches.
type replayWindow struct {
	max    uint32 // 0 = no counter accepted yet (counters start at 1)
	bitmap uint32 // bit i set ⇒ counter (max - 1 - i) already accepted
}

// check returns a commit closure when c is acceptable; the caller must
// invoke it only after AEAD auth succeeds. On rejection the window is
// left untouched.
func (w *replayWindow) check(c uint32) (commit func(), err error) {
	switch {
	case w.max == 0:
		return func() { w.max = c }, nil
	case c > w.max:
		shift := c - w.max
		return func() {
			if shift >= 32 {
				w.bitmap = 0
			} else {
				w.bitmap = (w.bitmap << shift) | (1 << (shift - 1))
			}
			w.max = c
		}, nil
	case c == w.max, w.max-c > MessageCounterWindowSize:
		return nil, ErrReplayedMessageCounter
	default:
		bit := uint32(1) << (w.max - c - 1)
		if w.bitmap&bit != 0 {
			return nil, ErrReplayedMessageCounter
		}
		return func() { w.bitmap |= bit }, nil
	}
}

var _ transport.MessageSecurity = (*SessionManager)(nil)
