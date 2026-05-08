package main

import (
	"fmt"
	"net"
	"time"

	"go-matter/commissioning"
	"go-matter/message"
	"go-matter/transport"
)

// ControllerMessenger adapts the transport layer to the
// commissioning.CommissioningMessenger interface.
type ControllerMessenger struct {
	tm         *transport.TransportManager
	deviceAddr *net.UDPAddr
}

func (m *ControllerMessenger) SendMessage(frame *message.Frame) error {
	// Send unreliable by default for this simple sample.
	return m.tm.Send(m.deviceAddr, frame, false)
}

func main() {
	fmt.Println("Starting Matter Controller Sample...")

	ctrlPort := 5550
	devicePort := 5540
	deviceIP := net.ParseIP("127.0.0.1")
	deviceAddr := &net.UDPAddr{IP: deviceIP, Port: devicePort}

	// 1. Setup Transport (Security is nil for now)
	tm, err := transport.NewTransportManager(ctrlPort, nil)
	if err != nil {
		panic(err)
	}
	defer tm.Close()

	// Start Transport Listener
	go func() {
		fmt.Printf("Controller listening on %d...\n", ctrlPort)
		if err := tm.Start(func(frame *message.Frame, from *net.UDPAddr) {
			fmt.Printf("Controller received frame opcode=%#x exchange=%d payload=%d bytes from %s\n",
				byte(frame.PayloadHeader.Opcode),
				frame.PayloadHeader.ExchangeID,
				len(frame.Payload),
				from)
			// TODO: dispatch into Commissioner.HandleMessage(frame) when implemented.
		}); err != nil {
			fmt.Printf("Controller transport error: %v\n", err)
		}
	}()

	// Allow transport to start
	time.Sleep(100 * time.Millisecond)

	// 2. Initialize Commissioner
	messenger := &ControllerMessenger{
		tm:         tm,
		deviceAddr: deviceAddr,
	}
	commissioner := commissioning.NewCommissioner(messenger)

	// 3. Start PASE Handshake
	fmt.Println("Attempting to start PASE...")
	if err := commissioner.StartPASE(12345678); err != nil {
		fmt.Printf("Failed to start PASE: %v\n", err)
	}

	// Keep alive
	select {}
}
