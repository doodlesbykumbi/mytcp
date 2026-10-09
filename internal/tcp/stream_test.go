package tcp

import (
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

func TestStreamConnEcho(t *testing.T) {
	em := &fakeEmit{}
	s := NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0))
	ln := s.Listen(443)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	peerIP := net.IPv4(10, 0, 0, 1)
	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50000, DstPort: 443, Seq: 1, Flags: FlagSYN, Window: 65535,
	}); err != nil {
		t.Fatal(err)
	}
	// ACK the SYN-ACK (iss starts at 1000, SYN consumes 1 → sndNxt=1001)
	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50000, DstPort: 443, Seq: 2, Ack: 1001, Flags: FlagACK, Window: 65535,
	}); err != nil {
		t.Fatal(err)
	}

	var sc net.Conn
	select {
	case sc = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("no accept")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 16)
		n, err := sc.Read(buf)
		if err != nil || string(buf[:n]) != "ping" {
			t.Errorf("read: n=%d err=%v data=%q", n, err, buf[:n])
		}
		if _, err := sc.Write([]byte("pong")); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50000, DstPort: 443, Seq: 2, Ack: 1001,
		Flags: FlagACK | FlagPSH, Window: 65535, Payload: []byte("ping"),
	}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
