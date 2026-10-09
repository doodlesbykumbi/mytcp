package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/udp"
)

// udpQueue is how many datagrams a port holds before new ones are
// dropped. UDP promises nothing, so dropping is allowed.
const udpQueue = 16

// UDPPort is one bound UDP port: the smallest thing that can send a
// datagram and wait for the answer. It is all DNS needs. Datagrams for
// ports nobody bound are dropped silently; we send no ICMP port
// unreachable.
type UDPPort struct {
	s    *Stack
	port uint16
	in   chan udpIn
	done chan struct{}
	once sync.Once
}

type udpIn struct {
	payload []byte
	ip      net.IP
	port    uint16
}

// udpPorts holds the bound ports. It has its own lock: UDP shares nothing
// with TCP's connection table.
type udpPorts struct {
	mu    sync.Mutex
	bound map[uint16]*UDPPort
	next  uint32 // ephemeral port cursor, as in tcp.Stack.Dial
}

// BindUDP claims a local UDP port. Port 0 picks a free ephemeral port.
func (s *Stack) BindUDP(port uint16) (*UDPPort, error) {
	s.udp.mu.Lock()
	defer s.udp.mu.Unlock()
	if port == 0 {
		for range 16384 {
			p := uint16(49152 + s.udp.next%16384)
			s.udp.next++
			if _, used := s.udp.bound[p]; !used {
				port = p
				break
			}
		}
		if port == 0 {
			return nil, errors.New("udp: no free ephemeral port")
		}
	} else if _, used := s.udp.bound[port]; used {
		return nil, fmt.Errorf("udp: port %d already bound", port)
	}
	u := &UDPPort{s: s, port: port, in: make(chan udpIn, udpQueue), done: make(chan struct{})}
	s.udp.bound[port] = u
	return u, nil
}

// Port is the local port number.
func (u *UDPPort) Port() uint16 { return u.port }

// WriteTo sends one datagram to ip:port. It may wait for ARP first.
func (u *UDPPort) WriteTo(ctx context.Context, payload []byte, ip net.IP, port uint16) error {
	ip = ip.To4()
	if ip == nil {
		return errors.New("udp: IPv4 only")
	}
	mac, err := u.s.Resolve(ctx, ip)
	if err != nil {
		return err
	}
	d := udp.Datagram{SrcPort: u.port, DstPort: port, Payload: payload}
	return u.s.sendIPv4(mac, ip, ip4.ProtoUDP, d.Encode(u.s.cfg.IP, ip))
}

// ReadFrom waits for the next datagram on this port and says who sent it.
func (u *UDPPort) ReadFrom(ctx context.Context) ([]byte, net.IP, uint16, error) {
	select {
	case d := <-u.in:
		return d.payload, d.ip, d.port, nil
	case <-u.done:
		return nil, nil, 0, net.ErrClosed
	case <-ctx.Done():
		return nil, nil, 0, ctx.Err()
	}
}

// Close frees the port.
func (u *UDPPort) Close() error {
	u.once.Do(func() {
		close(u.done)
		u.s.udp.mu.Lock()
		if u.s.udp.bound[u.port] == u {
			delete(u.s.udp.bound, u.port)
		}
		u.s.udp.mu.Unlock()
	})
	return nil
}

// handleUDP hands a datagram to its bound port, or drops it.
func (s *Stack) handleUDP(pkt ip4.Packet) error {
	d, err := udp.Decode(pkt.Payload)
	if err != nil {
		return err
	}
	s.log.Printf("udp: %s:%d → :%d len=%d", pkt.Src, d.SrcPort, d.DstPort, len(d.Payload))
	s.udp.mu.Lock()
	u := s.udp.bound[d.DstPort]
	s.udp.mu.Unlock()
	if u == nil {
		return nil
	}
	select {
	case u.in <- udpIn{payload: d.Payload, ip: pkt.Src, port: d.SrcPort}:
	default:
		s.log.Printf("udp: port %d queue full, dropped", d.DstPort)
	}
	return nil
}
