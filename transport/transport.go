package transport

import (
	"fmt"
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

// ReadHandler defines the callback for received packets.
type ReadHandler func(payload []byte, from *net.UDPAddr)

// TransportManager handles sending and receiving messages over UDP.
type TransportManager struct {
	conn            *net.UDPConn
	security        MessageSecurity
	unackedMessages map[uint32]interface{}
}

// NewTransportManager creates a new TransportManager listening on the specified port.
func NewTransportManager(port int, security MessageSecurity) (*TransportManager, error) {
	addr := &net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on udp port %d: %w", port, err)
	}
	return &TransportManager{
		conn:     conn,
		security: security,
	}, nil
}

// Send sends a message to the specified address.
// It handles MRP (Message Reliability Protocol) logic if reliable delivery is requested.
func (tm *TransportManager) Send(addr *net.UDPAddr, payload []byte, reliable bool) error {
	// TODO: Use security to encrypt payload?
	// For now, raw send for PASE sample scaffold
	_, err := tm.conn.WriteToUDP(payload, addr)
	return err
}

// Start starts the receiving loop.
func (tm *TransportManager) Start(handler ReadHandler) error {
	buf := make([]byte, 2048)
	for {
		n, addr, err := tm.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		// Copy payload
		payload := make([]byte, n)
		copy(payload, buf[:n])

		// TODO: Decrypt using tm.security?

		if handler != nil {
			handler(payload, addr)
		}
	}
}

// Close closes the transport connection.
func (tm *TransportManager) Close() error {
	if tm.conn != nil {
		return tm.conn.Close()
	}
	return nil
}
