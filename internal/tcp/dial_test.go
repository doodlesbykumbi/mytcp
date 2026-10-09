package tcp

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"syscall"
	"testing"
	"time"
)

var serverIP = net.IPv4(10, 0, 0, 1)

func dialStack() (*Stack, *fakeEmit) {
	em := &fakeEmit{}
	return NewStack(net.IPv4(10, 0, 0, 2), em, log.New(io.Discard, "", 0)), em
}

type dialResult struct {
	c   *StreamConn
	err error
}

func dialAsync(ctx context.Context, s *Stack, port uint16) <-chan dialResult {
	ch := make(chan dialResult, 1)
	go func() {
		c, err := s.Dial(ctx, serverIP, port)
		ch <- dialResult{c, err}
	}()
	return ch
}

// waitSend polls until the stack has sent its nth segment and returns it.
func waitSend(t *testing.T, em *fakeEmit, n int) Segment {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if got, seg := em.sent(); got >= n {
			return seg
		}
	}
	t.Fatalf("segment %d never sent", n)
	return Segment{}
}

func TestDialHandshakeAndData(t *testing.T) {
	s, em := dialStack()
	res := dialAsync(context.Background(), s, 9000)

	syn := waitSend(t, em, 1)
	if syn.Flags != FlagSYN || syn.DstPort != 9000 || syn.SrcPort < ephemeralFirst {
		t.Fatalf("first segment = %s %d→%d, want SYN from an ephemeral port", FlagsString(syn.Flags), syn.SrcPort, syn.DstPort)
	}

	// Server's SYN+ACK: its ISN is 5000, and it acks our SYN.
	if err := s.Handle(nil, serverIP, Segment{
		SrcPort: 9000, DstPort: syn.SrcPort, Seq: 5000, Ack: syn.Seq + 1,
		Flags: FlagSYN | FlagACK, Window: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	if _, ack := em.sent(); ack.Flags != FlagACK || ack.Ack != 5001 {
		t.Fatalf("third step = %s ack=%d, want ACK ack=5001", FlagsString(ack.Flags), ack.Ack)
	}

	if _, err := r.c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, out := em.sent(); string(out.Payload) != "hi" || out.Seq != syn.Seq+1 {
		t.Fatalf("data seg = %q seq=%d, want \"hi\" seq=%d", out.Payload, out.Seq, syn.Seq+1)
	}

	if err := s.Handle(nil, serverIP, Segment{
		SrcPort: 9000, DstPort: syn.SrcPort, Seq: 5001, Ack: syn.Seq + 3,
		Flags: FlagACK | FlagPSH, Window: 1000, Payload: []byte("yo"),
	}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := r.c.Read(buf)
	if err != nil || string(buf[:n]) != "yo" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
}

func TestDialRefused(t *testing.T) {
	s, em := dialStack()
	res := dialAsync(context.Background(), s, 9001)
	syn := waitSend(t, em, 1)

	if err := s.Handle(nil, serverIP, Segment{
		SrcPort: 9001, DstPort: syn.SrcPort, Ack: syn.Seq + 1, Flags: FlagRST | FlagACK,
	}); err != nil {
		t.Fatal(err)
	}
	if r := <-res; !errors.Is(r.err, syscall.ECONNREFUSED) {
		t.Fatalf("Dial err = %v, want connection refused", r.err)
	}
	if len(s.conns) != 0 {
		t.Fatalf("%d conns left after refusal", len(s.conns))
	}
}

func TestDialContextCancel(t *testing.T) {
	s, em := dialStack()
	ctx, cancel := context.WithCancel(context.Background())
	res := dialAsync(ctx, s, 9002)
	waitSend(t, em, 1)
	cancel()
	if r := <-res; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("Dial err = %v, want context.Canceled", r.err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) != 0 {
		t.Fatalf("%d conns left after cancel", len(s.conns))
	}
}

func TestDialTimeout(t *testing.T) {
	s, em := dialStack()
	now := time.Unix(0, 0)
	s.mu.Lock()
	s.now = func() time.Time { return now }
	s.mu.Unlock()
	res := dialAsync(context.Background(), s, 9003)
	waitSend(t, em, 1)
	for i := 0; i <= s.maxRetry; i++ {
		s.mu.Lock()
		now = now.Add(s.rto + time.Millisecond)
		s.mu.Unlock()
		s.Tick()
	}
	if r := <-res; !errors.Is(r.err, syscall.ETIMEDOUT) {
		t.Fatalf("Dial err = %v, want timeout", r.err)
	}
}

func TestDialPicksDistinctPorts(t *testing.T) {
	s, em := dialStack()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialAsync(ctx, s, 80)
	first := waitSend(t, em, 1)
	dialAsync(ctx, s, 80)
	second := waitSend(t, em, 2)
	if first.SrcPort == second.SrcPort {
		t.Fatalf("both dials used port %d", first.SrcPort)
	}
}
