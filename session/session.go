// Package session owns Matter's encryption boundary: it holds the per-direction
// AES-128-CCM keys derived from PASE/CASE, drives the outbound message counter,
// and enforces the inbound replay window. Session ID 0 is the unsecured-channel
// sentinel; encrypt and decrypt are pass-through for it (Matter §4.5; see
// docs/Messaging_Architecture.md).
package session

import (
	"errors"
	"fmt"

	"go-matter/crypto"
	"go-matter/message"
	"go-matter/transport"
)

// UnsecuredSessionID is the sentinel session that carries handshake traffic
// (PASE PBKDFParamRequest..Pake3, CASE Sigma1..Sigma3). The session table
// holds no entry for it; Encrypt/Decrypt return their input untouched.
const UnsecuredSessionID uint16 = 0

// MessageCounterWindowSize is the unicast-secured replay window per Matter
// Core Spec §4.5.4.2. Matches CHIP_CONFIG_MESSAGE_COUNTER_WINDOW_SIZE in
// connectedhomeip.
const MessageCounterWindowSize uint32 = 32

var (
	// ErrUnknownSession is returned when a secured frame references a
	// session ID that has no installed keys.
	ErrUnknownSession = errors.New("session: unknown session id")
	// ErrReplayedMessageCounter is returned when the inbound counter is
	// either a duplicate of one already in the window or older than the
	// window's left edge.
	ErrReplayedMessageCounter = errors.New("session: replayed message counter")
)

// PayloadHandler defines the interface for handling decrypted messages.
// This allows the session layer to pass data to the application layer without
// depending on it.
type PayloadHandler interface {
	HandlePayload(sessionID uint16, payload []byte) error
}

// Role indicates which direction this side of the session encrypts on.
// Resolved once at session install so the hot path never branches on role.
type Role int

const (
	RoleInitiator Role = iota
	RoleResponder
)

// Session is a single secure session: a pair of AES-128-CCM keys, a
// strictly-monotonic outbound counter, and an inbound replay window.
// Not to be confused with the "Secure Channel" *protocol* (ProtocolID
// 0x0000, see message/opcodes.go) which owns PASE/CASE/MRP/Status opcodes
// and runs *inside* a Session's encrypted payload (or on session 0 for
// the handshake itself).
//
// The receiver-side replay window only handles unicast secured sessions;
// group sessions (Matter §4.5.4.2 group rules + MSG_COUNTER_SYNC_REQ) are
// not in scope yet — see TODO §17-18.
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

// NextOutboundCounter increments the outbound message counter and returns the
// new value. The caller stamps this counter into the message header before
// calling EncryptPayload; the session itself reads the counter back from the
// header bytes so the AAD (cleartext header) and the AES-CCM nonce stay in
// lockstep.
//
// Returns crypto.ErrCounterExhausted before the counter would wrap; the
// session keys must then be retired (Matter §4.5.1.1).
func (s *Session) NextOutboundCounter() (uint32, error) {
	if s.OutCounter == ^uint32(0) {
		return 0, crypto.ErrCounterExhausted
	}
	s.OutCounter++
	return s.OutCounter, nil
}

// SessionManager owns the table of installed secure sessions and implements
// transport.MessageSecurity. Not safe for concurrent use — once the exchange
// manager (TODO §18) lands it will serialise access per session.
type SessionManager struct {
	sessions map[uint16]*Session
	handler  PayloadHandler
	provider crypto.CryptoProvider
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(handler PayloadHandler) *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
		handler:  handler,
		provider: &crypto.DefaultCryptoProvider{},
	}
}

// InstallSecureSession registers a session whose keys have just been derived
// from a completed PASE or CASE handshake. The role argument resolves which
// of (I2RKey, R2IKey) is the local encrypt key vs the peer decrypt key once
// and for all — the hot encrypt/decrypt paths never re-check it.
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

// Session returns the installed session for id, or (nil, false) when there is
// no entry. Session 0 (unsecured) intentionally has no entry.
func (sm *SessionManager) Session(id uint16) (*Session, bool) {
	s, ok := sm.sessions[id]
	return s, ok
}

// EncryptPayload seals payload with AES-128-CCM under the session's local-side
// key. The header bytes must already carry the outbound message counter
// (callers obtain it from Session.NextOutboundCounter) and become the AEAD's
// AAD — Matter authenticates the cleartext header even though it isn't
// encrypted (§4.5.3). Implements transport.MessageSecurity.
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

// DecryptPayload opens an AES-128-CCM ciphertext under the session's peer-side
// key. The header bytes are parsed twice's worth of information: their
// MessageCounter / SecurityFlags / SourceNodeID rebuild the nonce, and the
// bytes themselves are the AAD. The replay window only commits the counter
// after AEAD auth succeeds — otherwise a tampered frame could open a gap an
// attacker would later fill (§4.5.4.2). Implements transport.MessageSecurity.
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
// accepted message counters. Unicast counters never wrap (Matter §4.5.1.1;
// senders retire the session before 2^32-1 via crypto.ErrCounterExhausted),
// so plain unsigned comparison is sufficient and the §4.5.4.2 mod-2^32
// rules collapse to three branches.
//
// Not safe for concurrent use.
type replayWindow struct {
	// max is the highest counter accepted so far; 0 means none yet,
	// which doubles as the spec's "uninitialised" state (Matter mandates
	// outbound counters start at 1, so 0 cannot legitimately be observed).
	max uint32
	// bitmap bit i is set when counter (max - 1 - i) has already been
	// accepted, for i in [0, MessageCounterWindowSize).
	bitmap uint32
}

// check tests whether c is acceptable on this session. On success it returns
// a commit closure that mutates the window; the caller invokes it after AEAD
// auth succeeds. On rejection it returns ErrReplayedMessageCounter and leaves
// the window untouched.
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
