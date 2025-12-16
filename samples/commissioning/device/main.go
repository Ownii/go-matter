package main

import (
	"fmt"
	"go-matter/commissioning"
	"go-matter/transport"
	"net"
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
	err = tm.Start(func(payload []byte, from *net.UDPAddr) {
		fmt.Printf("Device received %d bytes from %s\n", len(payload), from)

		// Pass to Commissionee to handle
		// Since HandleMessage is a stub in current SDK state (reverted),
		// we just print that we got it.
		// TODO: When SDK is ready: if err := commissionee.HandleMessage(payload); ...
		err := commissionee.HandleMessage(payload)
		if err != nil {
			fmt.Printf("HandleMessage error: %v\n", err)
		} else {
			fmt.Println("Message handled (Stub).")
		}
	})

	if err != nil {
		fmt.Printf("Transport error: %v\n", err)
	}
}
