package main

import (
	"errors"
	"fmt"
	"net"

	"go-matter/commissioning"
	"go-matter/message"
	"go-matter/transport"
)

// deviceMessenger sends Commissionee replies back to the most recent peer.
// The transport read loop is single-threaded, so no synchronisation is needed.
type deviceMessenger struct {
	tm   *transport.TransportManager
	peer *net.UDPAddr
}

func (m *deviceMessenger) SendMessage(frame *message.Frame) error {
	if m.peer == nil {
		return errors.New("device messenger: no known peer")
	}
	return m.tm.Send(m.peer, frame, false)
}

func main() {
	const devicePort = 5540

	commissionee, err := commissioning.NewCommissionee(
		12345678, []byte("SPAKE2P Key Salt"), 1000)
	if err != nil {
		panic(err)
	}

	tm, err := transport.NewTransportManager(devicePort, nil)
	if err != nil {
		panic(err)
	}
	defer tm.Close()

	messenger := &deviceMessenger{tm: tm}
	commissionee.Messenger = messenger

	fmt.Printf("Device listening on %d...\n", devicePort)
	err = tm.Start(func(frame *message.Frame, from *net.UDPAddr) {
		fmt.Printf("Device <- opcode=%#x exchange=%d payload=%d bytes from %s\n",
			byte(frame.PayloadHeader.Opcode), frame.PayloadHeader.ExchangeID,
			len(frame.Payload), from)

		messenger.peer = from
		if err := commissionee.HandleMessage(frame); err != nil {
			fmt.Printf("HandleMessage error: %v\n", err)
			return
		}
		fmt.Printf("Commissionee state=%d sessionID=%d responderRandom=%x\n",
			commissionee.State, commissionee.SessionID, commissionee.Random)
	})
	if err != nil {
		fmt.Printf("Transport error: %v\n", err)
	}
}
