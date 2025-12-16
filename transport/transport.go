package transport

import (
	"net"
)

// MessageSecurity defines the interface for cryptographic processing of the payload.
// This interface allows the transport layer to be decoupled from the session layer.
type MessageSecurity interface {
	// EncryptPayload encrypts the message payload.
	EncryptPayload(sessionID uint16, payload []byte, header []byte) ([]byte, error)

	// DecryptPayload decrypts the message payload.
	DecryptPayload(sessionID uint16, ciphertext []byte, header []byte) ([]byte, error)
}

// TransportManager handles sending and receiving messages over UDP.
type TransportManager struct {
	conn            *net.UDPConn
	security        MessageSecurity
	unackedMessages map[uint32]interface{} // TODO: Define proper struct for tracking messages
}

// NewTransportManager creates a new TransportManager listening on the specified port.
func NewTransportManager(port int, security MessageSecurity) (*TransportManager, error) {
	// TODO: Initialize UDP connection
	return &TransportManager{
		security: security,
	}, nil
}

// Send sends a message to the specified address.
// It handles MRP (Message Reliability Protocol) logic if reliable delivery is requested.
func (tm *TransportManager) Send(addr *net.UDPAddr, payload []byte, reliable bool) error {
	// TODO: Implement sending logic
	// 1. Construct Message Header
	// 2. Encrypt Payload using tm.security
	// 3. Send via UDP
	// 4. If reliable, track for ACKs and retries
	return nil
}

// Listen starts the receiving loop.
func (tm *TransportManager) Listen() error {
	// TODO: Implement receive loop
	// 1. Read from UDP
	// 2. Parse Header
	// 3. Decrypt Payload using tm.security
	// 4. Handle ACKs
	// 5. Pass payload to upper layer (needs a callback or channel)
	return nil
}

// Close closes the transport connection.
func (tm *TransportManager) Close() error {
	if tm.conn != nil {
		return tm.conn.Close()
	}
	return nil
}
