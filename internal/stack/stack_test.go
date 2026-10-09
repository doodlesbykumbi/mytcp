package stack_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
	"github.com/doodlesbykumbi/mytcp/internal/icmp"
	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/stack"
	"github.com/doodlesbykumbi/mytcp/internal/tcp"
)

type memIF struct {
	mu   sync.Mutex
	rx   [][]byte
	tx   [][]byte
	name string
}

func (m *memIF) Name() string { return m.name }

func (m *memIF) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rx) == 0 {
		return 0, io.EOF
	}
	b := m.rx[0]
	m.rx = m.rx[1:]
	return copy(p, b), nil
}

func (m *memIF) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tx = append(m.tx, append([]byte(nil), p...))
	return len(p), nil
}

func (m *memIF) lastTX() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tx) == 0 {
		return nil
	}
	return m.tx[len(m.tx)-1]
}

func testStack(t *testing.T) (*stack.Stack, *memIF) {
	t.Helper()
	nif := &memIF{name: "test0"}
	st := stack.New(nif, stack.Config{
		MAC:    net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		IP:     net.IPv4(10, 0, 0, 2),
		Logger: log.New(io.Discard, "", 0),
	})
	// Echo on port 7, the way cmd/mytcp -app echo runs it.
	ln := st.TCP().Listen(7)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return st, nif
}

func TestARPReply(t *testing.T) {
	st, nif := testStack(t)
	req := arp.Packet{
		Op:  arp.OpRequest,
		SHA: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		SPA: net.IPv4(10, 0, 0, 1),
		THA: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		TPA: net.IPv4(10, 0, 0, 2),
	}
	frame := eth.Frame{
		Dst:     net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:     req.SHA,
		Type:    eth.TypeARP,
		Payload: req.Encode(),
	}
	if err := st.HandleFrame(frame.Encode()); err != nil {
		t.Fatal(err)
	}
	raw := nif.lastTX()
	if raw == nil {
		t.Fatal("no TX")
	}
	out, err := eth.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != eth.TypeARP {
		t.Fatalf("type=%s", eth.TypeName(out.Type))
	}
	rep, err := arp.Decode(out.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Op != arp.OpReply || !rep.SPA.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("bad reply %+v", rep)
	}
}

func TestICMPEcho(t *testing.T) {
	st, nif := testStack(t)
	echo := icmp.Echo{Type: icmp.TypeEcho, ID: 1, Seq: 1, Payload: []byte("hi")}
	ipPkt := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoICMP,
		Src: net.IPv4(10, 0, 0, 1), Dst: net.IPv4(10, 0, 0, 2),
		Payload: echo.Encode(),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Type: eth.TypeIPv4, Payload: ipPkt.Encode(),
	}
	if err := st.HandleFrame(frame.Encode()); err != nil {
		t.Fatal(err)
	}
	raw := nif.lastTX()
	out, err := eth.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ip4.Decode(out.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := icmp.Decode(ip.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Type != icmp.TypeEchoReply || !bytes.Equal(rep.Payload, []byte("hi")) {
		t.Fatalf("bad icmp %+v", rep)
	}
}

func TestTCPHandshakeAndEcho(t *testing.T) {
	st, nif := testStack(t)
	peerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	peerIP := net.IPv4(10, 0, 0, 1)
	ourIP := net.IPv4(10, 0, 0, 2)

	sendTCP := func(seg tcp.Segment) {
		t.Helper()
		ipPkt := ip4.Packet{
			TTL: 64, Proto: ip4.ProtoTCP,
			Src: peerIP, Dst: ourIP,
			Payload: seg.Encode(peerIP, ourIP),
		}
		frame := eth.Frame{
			Dst: net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, Src: peerMAC,
			Type: eth.TypeIPv4, Payload: ipPkt.Encode(),
		}
		if err := st.HandleFrame(frame.Encode()); err != nil {
			t.Fatal(err)
		}
	}
	readTCP := func() tcp.Segment {
		t.Helper()
		raw := nif.lastTX()
		if raw == nil {
			t.Fatal("no TX")
		}
		f, err := eth.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ip4.Decode(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		seg, err := tcp.Decode(ip.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return seg
	}

	// SYN
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 500, Flags: tcp.FlagSYN, Window: 65535,
	})
	synAck := readTCP()
	if !synAck.Has(tcp.FlagSYN) || !synAck.Has(tcp.FlagACK) || synAck.Ack != 501 {
		t.Fatalf("SYN-ACK %+v flags=%s", synAck, tcp.FlagsString(synAck.Flags))
	}

	// ACK handshake
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 501, Ack: synAck.Seq + 1,
		Flags: tcp.FlagACK, Window: 65535,
	})

	// Data. The stack ACKs at once; the echo comes back from the app's
	// goroutine a moment later.
	payload := []byte("hello")
	sendTCP(tcp.Segment{
		SrcPort: 40000, DstPort: 7, Seq: 501, Ack: synAck.Seq + 1,
		Flags: tcp.FlagACK | tcp.FlagPSH, Window: 65535, Payload: payload,
	})
	var echo tcp.Segment
	for deadline := time.Now().Add(time.Second); ; {
		if echo = readTCP(); len(echo.Payload) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no echo")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !bytes.Equal(echo.Payload, payload) {
		t.Fatalf("echo %q", echo.Payload)
	}
	if echo.Ack != 501+uint32(len(payload)) {
		t.Fatalf("ack=%d", echo.Ack)
	}
}

// Ping replies (reader goroutine) and TCP sends (tick and TLS goroutines)
// share the IPv4 ID counter. Run with -race; every packet must get its own ID.
func TestConcurrentSendsGetDistinctIPIDs(t *testing.T) {
	st, nif := testStack(t)
	echo := icmp.Echo{Type: icmp.TypeEcho, ID: 1, Seq: 1, Payload: []byte("hi")}
	ping := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Type: eth.TypeIPv4,
		Payload: (&ip4.Packet{
			TTL: 64, Proto: ip4.ProtoICMP,
			Src: net.IPv4(10, 0, 0, 1), Dst: net.IPv4(10, 0, 0, 2),
			Payload: echo.Encode(),
		}).Encode(),
	}.Encode()

	const perWorker, workers = 200, 4
	var wg sync.WaitGroup
	wg.Add(workers)
	go func() {
		defer wg.Done()
		for i := 0; i < perWorker; i++ {
			if err := st.HandleFrame(ping); err != nil {
				t.Error(err)
			}
		}
	}()
	for w := 1; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				seg := tcp.Segment{SrcPort: 7, DstPort: 5000, Flags: tcp.FlagACK}
				if err := st.SendTCP(net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, net.IPv4(10, 0, 0, 1), seg); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	seen := map[uint16]bool{}
	for _, raw := range nif.tx {
		f, _ := eth.Decode(raw)
		p, err := ip4.Decode(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p.ID] {
			t.Fatalf("IPv4 ID %d used twice", p.ID)
		}
		seen[p.ID] = true
	}
	if len(seen) != perWorker*workers {
		t.Fatalf("got %d packets, want %d", len(seen), perWorker*workers)
	}
}
