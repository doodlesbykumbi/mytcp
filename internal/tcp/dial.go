package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Ephemeral ports, the range a dialing side picks its own port from
// (RFC 6335 section 6). Linux defaults to 32768-60999 instead.
const (
	ephemeralFirst = 49152
	ephemeralCount = 65536 - ephemeralFirst
)

// Dial opens a connection to ip:port, the active open, and returns it
// once the three-way handshake completes:
//
//	Resolve the next hop's MAC (ARP; may take a round trip)
//	pick an ephemeral local port
//	send SYN                      → SYN_SENT
//	recv SYN+ACK, send ACK        → ESTABLISHED, Dial returns
//
// It fails with syscall.ECONNREFUSED if the peer answers with a RST,
// syscall.ETIMEDOUT if the SYN is never answered, or ctx.Err() if ctx
// ends first.
func (s *Stack) Dial(ctx context.Context, ip net.IP, port uint16) (*StreamConn, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("tcp: dial %s: IPv4 only", ip)
	}
	// ARP can take a second or more, so it runs before taking s.mu.
	mac, err := s.emit.Resolve(ctx, ip4)
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s:%d: %w", ip4, port, err)
	}

	s.mu.Lock()
	lport, err := s.ephemeralPortLocked(ip4, port)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	iss := s.iss
	s.iss += 100000
	key := fourTuple{remoteIP: ip4.String(), remotePort: port, localPort: lport}
	c := &Conn{
		tuple:      key,
		state:      StateSynSent,
		remoteIP:   append(net.IP(nil), ip4...),
		remoteMAC:  append(net.HardwareAddr(nil), mac...),
		localPort:  lport,
		remotePort: port,
		sndUna:     iss,
		sndNxt:     iss,
		rcvWnd:     65535,
		dialDone:   make(chan error, 1),
	}
	s.conns[key] = c
	s.log.Printf("tcp: dial %s:%d from :%d → SYN_SENT", ip4, port, lport)
	// Our SYN takes one sequence number; sendCtrlLocked counts it and
	// queues the SYN for retransmission.
	err = s.sendCtrlLocked(c, FlagSYN, nil)
	if err != nil {
		s.destroyLocked(c)
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case err := <-c.dialDone:
		if err != nil {
			return nil, fmt.Errorf("tcp: dial %s:%d: %w", ip4, port, err)
		}
		return c.stream, nil
	case <-ctx.Done():
		s.mu.Lock()
		defer s.mu.Unlock()
		if c.state == StateSynSent {
			s.destroyLocked(c)
			return nil, ctx.Err()
		}
		// The handshake finished or failed just as ctx ended; report that.
		if err := <-c.dialDone; err != nil {
			return nil, fmt.Errorf("tcp: dial %s:%d: %w", ip4, port, err)
		}
		return c.stream, nil
	}
}

// ephemeralPortLocked returns a local port that is not listening and not
// already part of a connection to ip:port. Without TIME_WAIT a port can
// be reused right after a close; the peer's own TIME_WAIT then protects
// it from stray old segments only if the ISN moved on, which it does.
func (s *Stack) ephemeralPortLocked(ip net.IP, port uint16) (uint16, error) {
	for range ephemeralCount {
		p := uint16(ephemeralFirst + s.nextPort%ephemeralCount)
		s.nextPort++
		if _, ok := s.listen[p]; ok {
			continue
		}
		if _, ok := s.conns[fourTuple{remoteIP: ip.String(), remotePort: port, localPort: p}]; ok {
			continue
		}
		return p, nil
	}
	return 0, errors.New("tcp: no free ephemeral port")
}

// failDialLocked ends a connection still in SYN_SENT and tells Dial why.
func (s *Stack) failDialLocked(c *Conn, err error) {
	if c.state != StateSynSent {
		return
	}
	c.state = StateClosed
	s.destroyLocked(c)
	c.dialDone <- err
}
