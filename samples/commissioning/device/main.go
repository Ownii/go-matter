package main

import (
	"fmt"
	"net"
	"sync"

	"go-matter/commissioning"
	"go-matter/message"
	"go-matter/transport"
)

// deviceMessenger captures the source UDPAddr of the most recently received
// frame so that replies built by the Commissionee can be sent back to the
// originating controller. The Commissionee speaks one exchange at a time
// during PASE, so a single peer slot is sufficient for the sample.
type deviceMessenger struct {
	tm   *transport.TransportManager
	mu   sync.Mutex
	peer *net.UDPAddr
}

func (m *deviceMessenger) setPeer(addr *net.UDPAddr) {
	m.mu.Lock()
	m.peer = addr
	m.mu.Unlock()
}

func (m *deviceMessenger) SendMessage(frame *message.Frame) error {
	m.mu.Lock()
	peer := m.peer
	m.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("device messenger: no known peer to reply to")
	}
	return m.tm.Send(peer, frame, false)
}

func main() {
	fmt.Println("Starting Matter Device Sample...")

	devicePort := 5540

	// Create Commissionee (Passcode: 12345678). Salt/iterations match the
	// canonical Matter test fixture so paired controllers can reproduce.
	commissionee, err := commissioning.NewCommissionee(
		12345678, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		panic(err)
	}

	// 1. Setup Transport
	tm, err := transport.NewTransportManager(devicePort, nil)
	if err != nil {
		panic(err)
	}
	defer tm.Close()

	messenger := &deviceMessenger{tm: tm}
	commissionee.Messenger = messenger

	fmt.Printf("Device listening on %d...\n", devicePort)

	// Start Transport and handle messages
	err = tm.Start(func(frame *message.Frame, from *net.UDPAddr) {
		fmt.Printf("Device received frame opcode=%#x exchange=%d payload=%d bytes from %s\n",
			byte(frame.PayloadHeader.Opcode),
			frame.PayloadHeader.ExchangeID,
			len(frame.Payload),
			from)

		messenger.setPeer(from)
		if err := commissionee.HandleMessage(frame); err != nil {
			fmt.Printf("HandleMessage error: %v\n", err)
			return
		}
		fmt.Printf("Commissionee state -> %d (responderSessionID=%d responderRandom=%x)\n",
			commissionee.State, commissionee.SessionID, commissionee.Random)
	})

	if err != nil {
		fmt.Printf("Transport error: %v\n", err)
	}
}
