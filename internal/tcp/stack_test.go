package tcp

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeEmit struct {
	mu   sync.Mutex
	n    int
	last Segment
}

func (f *fakeEmit) SendTCP(dstMAC net.HardwareAddr, dstIP net.IP, seg Segment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.last = seg
	return nil
}

func (f *fakeEmit) Resolve(ctx context.Context, ip net.IP) (net.HardwareAddr, error) {
	return net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, nil
}

// sent returns the send count and the latest segment.
func (f *fakeEmit) sent() (int, Segment) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n, f.last
}

func TestRetransmitTick(t *testing.T) {
	em := &fakeEmit{}
	s := NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0))
	s.rto = 50 * time.Millisecond
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	s.Listen(7)
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	if err := s.Handle(peerMAC, net.IPv4(10, 0, 0, 1), Segment{
		SrcPort: 40000, DstPort: 7, Seq: 1, Flags: FlagSYN, Window: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if em.n != 1 {
		t.Fatalf("expected SYN-ACK send, got %d", em.n)
	}

	now = now.Add(60 * time.Millisecond)
	s.Tick()
	if em.n != 2 {
		t.Fatalf("expected retransmit, got %d sends", em.n)
	}
}

func TestNoRSTForRST(t *testing.T) {
	em := &fakeEmit{}
	s := NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0))
	if err := s.Handle(nil, net.IPv4(10, 0, 0, 1), Segment{
		SrcPort: 9000, DstPort: 49152, Seq: 7, Flags: FlagRST,
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := em.sent(); n != 0 {
		t.Fatalf("answered a stray RST with %d segments", n)
	}
}
