package stack

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
)

// arpTries is how many ARP requests Resolve sends before giving up.
const arpTries = 3

// neighbors is the ARP cache: which MAC owns each IP on our link. Entries
// never expire; a real stack ages them out after a minute or so.
//
// A sender that is waiting for an answer gets a channel that is closed
// when the answer arrives, so several waiters for the same IP share one.
type neighbors struct {
	mu      sync.Mutex
	macs    map[string]net.HardwareAddr
	waiting map[string]chan struct{}
}

func newNeighbors() *neighbors {
	return &neighbors{
		macs:    make(map[string]net.HardwareAddr),
		waiting: make(map[string]chan struct{}),
	}
}

// get returns the cached MAC for ip, or, if there is none yet, a channel
// that closes once learn records it.
func (n *neighbors) get(ip net.IP) (net.HardwareAddr, <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := ip.String()
	if mac, ok := n.macs[key]; ok {
		return mac, nil
	}
	ch, ok := n.waiting[key]
	if !ok {
		ch = make(chan struct{})
		n.waiting[key] = ch
	}
	return nil, ch
}

// learn records that ip is at mac and wakes anyone waiting for it.
func (n *neighbors) learn(ip net.IP, mac net.HardwareAddr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	key := ip.String()
	n.macs[key] = append(net.HardwareAddr(nil), mac...)
	if ch, ok := n.waiting[key]; ok {
		close(ch)
		delete(n.waiting, key)
	}
}

// nextHop picks who an IPv4 packet for dst is handed to on the link. On
// our subnet that is dst itself; anywhere else it is the gateway, and the
// IPv4 header still names dst. With no subnet configured, everything is
// treated as on-link.
func (s *Stack) nextHop(dst net.IP) (net.IP, error) {
	if s.cfg.Subnet == nil || s.cfg.Subnet.Contains(dst) {
		return dst, nil
	}
	if s.cfg.Gateway == nil {
		return nil, fmt.Errorf("no route to %s: not on %s and no gateway", dst, s.cfg.Subnet)
	}
	return s.cfg.Gateway, nil
}

// Resolve returns the MAC to put in the Ethernet header of a packet for
// dst: the MAC of the next hop. On a cache miss it broadcasts an ARP
// request and waits for the reply, asking up to arpTries times. It
// implements the lookup half of tcp.Emitter.
func (s *Stack) Resolve(ctx context.Context, dst net.IP) (net.HardwareAddr, error) {
	hop, err := s.nextHop(dst)
	if err != nil {
		return nil, err
	}
	for try := 0; try < arpTries; try++ {
		mac, ready := s.neigh.get(hop)
		if mac != nil {
			return mac, nil
		}
		s.log.Printf("arp: who-has %s tell %s", hop, s.cfg.IP)
		if err := s.sendARPRequest(hop); err != nil {
			return nil, err
		}
		t := time.NewTimer(s.arpRetry)
		select {
		case <-ready:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		}
		t.Stop()
	}
	if mac, _ := s.neigh.get(hop); mac != nil {
		return mac, nil
	}
	return nil, fmt.Errorf("arp: no reply from %s", hop)
}

// sendARPRequest broadcasts "who has target? tell ourIP".
func (s *Stack) sendARPRequest(target net.IP) error {
	req := arp.RequestFor(s.cfg.MAC, s.cfg.IP, target)
	return s.writeFrame(eth.Frame{
		Dst:     net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:     s.cfg.MAC,
		Type:    eth.TypeARP,
		Payload: req.Encode(),
	})
}
