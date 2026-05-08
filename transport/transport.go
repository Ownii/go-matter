package transport

import (
	"fmt"
	"net"
	"os"

	"go-matter/message"
)

// MessageSecurity defines the interface for cryptographic processing of the payload.
// This interface allows the transport layer to be decoupled from the session layer.
type MessageSecurity interface {
	// EncryptPayload encrypts the message payload.
	EncryptPayload(sessionID uint16, payload []byte, header []byte) ([]byte, error)

	// DecryptPayload decrypts the message payload.
	DecryptPayload(sessionID uint16, ciphertext []byte, header []byte) ([]byte, error)
}

// ReadHandler defines the callback for received frames.
type ReadHandler func(frame *message.Frame, from *net.UDPAddr)

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

// Send serialises the frame and writes it to the destination address.
// MRP behaviour for reliable delivery is not implemented yet (TODO §17).
func (tm *TransportManager) Send(addr *net.UDPAddr, frame *message.Frame, reliable bool) error {
	// TODO: MRP retransmission table when reliable == true.
	// TODO: Encrypt frame.Payload via tm.security once secure sessions land.
	wire, err := frame.Encode()
	if err != nil {
		return fmt.Errorf("transport: encode frame: %w", err)
	}
	_, err = tm.conn.WriteToUDP(wire, addr)
	return err
}

// Start runs the receive loop, decoding each datagram into a Frame and
// dispatching it to the handler. Malformed datagrams are logged and dropped.
func (tm *TransportManager) Start(handler ReadHandler) error {
	buf := make([]byte, 2048)
	for {
		n, addr, err := tm.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		// TODO: Decrypt the post-header portion via tm.security for secured sessions.
		frame, err := message.Decode(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "transport: drop malformed packet from %s: %v\n", addr, err)
			continue
		}

		if handler != nil {
			handler(frame, addr)
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
