package tcp

import (
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestListenerAccept(t *testing.T) {
	em := &fakeEmit{}
	s := NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0))
	ln := s.Listen(80)

	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	peerIP := net.IPv4(10, 0, 0, 1)

	done := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		done <- c
	}()

	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50000, DstPort: 80, Seq: 1, Flags: FlagSYN, Window: 65535,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50000, DstPort: 80, Seq: 2, Ack: 1001, Flags: FlagACK, Window: 65535,
	}); err != nil {
		t.Fatal(err)
	}

	var c net.Conn
	select {
	case c = <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept did not return")
	}
	defer c.Close()

	if _, ok := c.(*StreamConn); !ok {
		t.Fatalf("Accept returned %T, want *StreamConn", c)
	}
	if got, want := c.LocalAddr().String(), "10.0.0.2:80"; got != want {
		t.Fatalf("LocalAddr = %s, want %s", got, want)
	}
	if got, want := ln.Addr().String(), "10.0.0.2:80"; got != want {
		t.Fatalf("Listener.Addr = %s, want %s", got, want)
	}

	_ = ln.Close()
	if _, err := ln.Accept(); err != net.ErrClosed {
		t.Fatalf("Accept after Close: %v", err)
	}

	// A closed Listener frees its port: the next SYN is refused.
	if err := s.Handle(peerMAC, peerIP, Segment{
		SrcPort: 50001, DstPort: 80, Seq: 1, Flags: FlagSYN, Window: 65535,
	}); err != nil {
		t.Fatal(err)
	}
	if !em.last.Has(FlagRST) {
		t.Fatalf("SYN after Close got %s, want RST", FlagsString(em.last.Flags))
	}
}
