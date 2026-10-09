package tcp

import (
	"net"
	"sync"
)

// Compile-time checks: StreamConn is a net.Conn, Listener is a net.Listener.
// That is the contract Go's stdlib (net/http, crypto/tls) expects of a
// transport, so anything that works on a kernel socket works on ours.
var (
	_ net.Conn     = (*StreamConn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// Listener is a net.Listener for one port on this userspace TCP stack.
// The stack pushes each connection that reaches ESTABLISHED; Accept pulls
// them off a channel, one per call.
type Listener struct {
	stack *Stack
	port  uint16
	addr  net.Addr

	ch   chan *StreamConn
	done chan struct{}
	once sync.Once
}

// Listen opens port for incoming connections and returns its Listener.
// SYNs to ports nobody listens on are answered with RST. Listening twice
// on the same port replaces the earlier Listener.
func (s *Stack) Listen(port uint16) *Listener {
	ln := &Listener{
		stack: s,
		port:  port,
		addr:  &net.TCPAddr{IP: append(net.IP(nil), s.ourIP...), Port: int(port)},
		ch:    make(chan *StreamConn),
		done:  make(chan struct{}),
	}
	s.mu.Lock()
	s.listen[port] = ln
	s.mu.Unlock()
	s.log.Printf("tcp: LISTEN :%d", port)
	return ln
}

// push hands a new connection to Accept. Handle calls it on its own
// goroutine, so blocking here until someone Accepts does not stall
// other traffic.
func (l *Listener) push(c *StreamConn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// Accept waits for the next ESTABLISHED connection and returns it as a
// net.Conn (*StreamConn). It returns net.ErrClosed after Close.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and frees the port, so new SYNs get RST.
// In-flight Accept calls return net.ErrClosed. Connections already handed
// out are not closed.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.stack.mu.Lock()
		if l.stack.listen[l.port] == l {
			delete(l.stack.listen, l.port)
		}
		l.stack.mu.Unlock()
	})
	return nil
}

// Addr returns the local IP and listen port as a *net.TCPAddr.
func (l *Listener) Addr() net.Addr { return l.addr }
