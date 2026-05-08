package main

import (
	"fmt"
	"net"

	"go-matter/commissioning"
	"go-matter/message"
	"go-matter/transport"
)

func main() {
	fmt.Println("Starting Matter Device Sample...")

	devicePort := 5540

	// Create Commissionee (Passcode: 12345678)
	commissionee := commissioning.NewCommissionee(12345678)

	// 1. Setup Transport
	tm, err := transport.NewTransportManager(devicePort, nil)
	if err != nil {
		panic(err)
	}
	defer tm.Close()

	fmt.Printf("Device listening on %d...\n", devicePort)

	// Start Transport and handle messages
	err = tm.Start(func(frame *message.Frame, from *net.UDPAddr) {
		fmt.Printf("Device received frame opcode=%#x exchange=%d payload=%d bytes from %s\n",
			byte(frame.PayloadHeader.Opcode),
			frame.PayloadHeader.ExchangeID,
			len(frame.Payload),
			from)

		// HandleMessage is a stub today (TODO §19-21); call it so the wiring
		// is visibly correct end to end.
		if err := commissionee.HandleMessage(frame); err != nil {
			fmt.Printf("HandleMessage error: %v\n", err)
		} else {
			fmt.Println("Frame handled (stub).")
		}
	})

	if err != nil {
		fmt.Printf("Transport error: %v\n", err)
	}
}
