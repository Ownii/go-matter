package main

import (
	"fmt"
	"net"
	"time"

	"go-matter/commissioning"
	"go-matter/message"
	"go-matter/session"
	"go-matter/transport"
)

type controllerMessenger struct {
	tm         *transport.TransportManager
	deviceAddr *net.UDPAddr
}

func (m *controllerMessenger) SendMessage(frame *message.Frame) error {
	return m.tm.Send(m.deviceAddr, frame, false)
}

func main() {
	const ctrlPort = 5550
	const devicePort = 5540
	deviceAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: devicePort}

	tm, err := transport.NewTransportManager(ctrlPort, nil)
	if err != nil {
		panic(err)
	}
	defer tm.Close()

	sm := session.NewSessionManager(nil)
	commissioner := commissioning.NewCommissioner(&controllerMessenger{tm: tm, deviceAddr: deviceAddr}, sm)

	go func() {
		fmt.Printf("Controller listening on %d...\n", ctrlPort)
		if err := tm.Start(func(frame *message.Frame, from *net.UDPAddr) {
			fmt.Printf("Controller <- opcode=%#x exchange=%d payload=%d bytes from %s\n",
				byte(frame.PayloadHeader.Opcode), frame.PayloadHeader.ExchangeID,
				len(frame.Payload), from)
			if err := commissioner.HandleMessage(frame); err != nil {
				fmt.Printf("HandleMessage error: %v\n", err)
				return
			}
			fmt.Printf("Commissioner state=%d salt=%x iterations=%d responderSessionID=%d\n",
				commissioner.State, commissioner.Salt, commissioner.Iterations,
				commissioner.ResponderSessionID)
		}); err != nil {
			fmt.Printf("Transport error: %v\n", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := commissioner.StartPASE(12345678); err != nil {
		fmt.Printf("StartPASE: %v\n", err)
	}
	select {}
}
