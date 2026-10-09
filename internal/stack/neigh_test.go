package stack_test

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
	"github.com/doodlesbykumbi/mytcp/internal/stack"
)

var (
	ourMAC    = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	ourIP     = net.IPv4(10, 0, 0, 2)
	gwMAC     = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	gwIP      = net.IPv4(10, 0, 0, 1)
	_, lan, _ = net.ParseCIDR("10.0.0.0/24")
)

func routedStack(t *testing.T) (*stack.Stack, *memIF) {
	t.Helper()
	nif := &memIF{name: "test0"}
	st := stack.New(nif, stack.Config{
		MAC: ourMAC, IP: ourIP, Subnet: lan, Gateway: gwIP,
		ARPRetry: 20 * time.Millisecond,
		Logger:   log.New(io.Discard, "", 0),
	})
	return st, nif
}

// waitARPRequest polls for our broadcast "who has target?".
func waitARPRequest(t *testing.T, nif *memIF, target net.IP) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		raw := nif.lastTX()
		if raw == nil {
			continue
		}
		f, err := eth.Decode(raw)
		if err != nil || f.Type != eth.TypeARP {
			continue
		}
		p, err := arp.Decode(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if p.Op != arp.OpRequest || !p.TPA.Equal(target) {
			t.Fatalf("got ARP %+v, want request for %s", p, target)
		}
		if f.Dst.String() != "ff:ff:ff:ff:ff:ff" {
			t.Fatalf("request sent to %s, want broadcast", f.Dst)
		}
		return
	}
	t.Fatalf("no ARP request for %s", target)
}

func feedARPReply(t *testing.T, st *stack.Stack, mac net.HardwareAddr, ip net.IP) {
	t.Helper()
	rep := arp.Packet{Op: arp.OpReply, SHA: mac, SPA: ip, THA: ourMAC, TPA: ourIP}
	f := eth.Frame{Dst: ourMAC, Src: mac, Type: eth.TypeARP, Payload: rep.Encode()}
	if err := st.HandleFrame(f.Encode()); err != nil {
		t.Fatal(err)
	}
}

func resolveAsync(st *stack.Stack, ip net.IP) <-chan net.HardwareAddr {
	ch := make(chan net.HardwareAddr, 1)
	go func() {
		mac, _ := st.Resolve(context.Background(), ip)
		ch <- mac
	}()
	return ch
}

func TestResolveOnLink(t *testing.T) {
	st, nif := routedStack(t)
	got := resolveAsync(st, gwIP)
	waitARPRequest(t, nif, gwIP)
	feedARPReply(t, st, gwMAC, gwIP)
	if mac := <-got; mac.String() != gwMAC.String() {
		t.Fatalf("Resolve = %v, want %v", mac, gwMAC)
	}

	// Now cached: no new frame goes out.
	n := len(nif.tx)
	mac, err := st.Resolve(context.Background(), gwIP)
	if err != nil || mac.String() != gwMAC.String() || len(nif.tx) != n {
		t.Fatalf("cached Resolve = %v, %v; sent %d new frames", mac, err, len(nif.tx)-n)
	}
}

func TestResolveOffLinkUsesGateway(t *testing.T) {
	st, nif := routedStack(t)
	google := net.IPv4(142, 251, 30, 113)
	got := resolveAsync(st, google)
	waitARPRequest(t, nif, gwIP)
	feedARPReply(t, st, gwMAC, gwIP)
	if mac := <-got; mac.String() != gwMAC.String() {
		t.Fatalf("Resolve(%s) = %v, want the gateway's MAC %v", google, mac, gwMAC)
	}
}

func TestResolveTimeout(t *testing.T) {
	st, nif := routedStack(t)
	if _, err := st.Resolve(context.Background(), net.IPv4(10, 0, 0, 9)); err == nil {
		t.Fatal("Resolve with no reply succeeded")
	}
	if len(nif.tx) != 3 {
		t.Fatalf("sent %d ARP requests, want 3", len(nif.tx))
	}
}
