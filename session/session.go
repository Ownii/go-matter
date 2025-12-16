package session

import (
	"go-matter/transport"
)

// PayloadHandler defines the interface for handling decrypted messages.
// This allows the session layer to pass data to the application layer without depending on it.
type PayloadHandler interface {
	// HandlePayload processes a decrypted message payload.
	HandlePayload(sessionID uint16, payload []byte) error
}

// Session represents a secure channel between two nodes.
type Session struct {
	ID         uint16
	PeerNodeID uint64
	Keys       []byte // TODO: Use proper key structure
	InCounter  uint32
	OutCounter uint32
}

// SessionManager manages multiple sessions.
type SessionManager struct {
	sessions map[uint16]*Session
	handler  PayloadHandler
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(handler PayloadHandler) *SessionManager {
	return &SessionManager{
		sessions: make(map[uint16]*Session),
		handler:  handler,
	}
}

// CreateSession creates a new session with the given ID and peer.
func (sm *SessionManager) CreateSession(id uint16, peerNodeID uint64) *Session {
	session := &Session{
		ID:         id,
		PeerNodeID: peerNodeID,
	}
	sm.sessions[id] = session
	return session
}

// EncryptPayload encrypts the message payload using the session keys.
// Implements transport.MessageSecurity.
func (sm *SessionManager) EncryptPayload(sessionID uint16, payload []byte, header []byte) ([]byte, error) {
	session, ok := sm.sessions[sessionID]
	if !ok {
		// TODO: Handle unknown session
		return nil, nil
	}
	// TODO: Implement encryption logic using session.Keys and session.OutCounter
	_ = session
	return payload, nil
}

// DecryptPayload decrypts the message payload using the session keys.
// Implements transport.MessageSecurity.
func (sm *SessionManager) DecryptPayload(sessionID uint16, ciphertext []byte, header []byte) ([]byte, error) {
	session, ok := sm.sessions[sessionID]
	if !ok {
		// TODO: Handle unknown session
		return nil, nil
	}
	// TODO: Implement decryption logic using session.Keys and update session.InCounter
	_ = session
	return ciphertext, nil
}

// Ensure SessionManager implements transport.MessageSecurity
var _ transport.MessageSecurity = (*SessionManager)(nil)
