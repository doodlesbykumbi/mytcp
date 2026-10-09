package tcp

import (
	"io"
	"net"
	"sync"
	"time"
)

// MaxSegPayload caps a single TCP data segment. 1200 bytes of payload
// plus 20 bytes of TCP header and 20 bytes of IPv4 header fits well under
// the usual 1500-byte Ethernet MTU of a TAP device, so segments never
// need IP fragmentation. We do not read the peer's MSS option; this fixed
// size stands in for it.
const MaxSegPayload = 1200

// StreamConn is a net.Conn backed by one userspace TCP connection. It lets
// ordinary Go code, such as crypto/tls or the hand-written TLS, run on top
// of this stack as if it were a kernel socket.
//
// Data flows like this:
//
//	incoming: Stack.Handle -> deliver -> rbuf -> Read
//	outgoing: Write -> Stack.writeStream -> one segment per chunk
//
// Locking: mu protects rbuf and the three flags; cond (tied to mu) wakes
// a blocked Read. The stack calls deliver, peerClosed and teardown while
// holding Stack.mu, so the lock order is Stack.mu, then StreamConn.mu.
// Write and Close release mu before calling into the stack, which keeps
// that order and avoids deadlock.
type StreamConn struct {
	stack *Stack
	tuple fourTuple

	local  net.Addr
	remote net.Addr

	mu      sync.Mutex
	cond    *sync.Cond
	rbuf    []byte // received, in-order bytes not yet Read; unbounded
	rClosed bool   // peer FIN / RST / local close — Read → EOF
	wClosed bool   // local Close called; Write fails
	dead    bool   // fully torn down
}

// newStreamConn wraps an ESTABLISHED connection. It only copies the
// addressing it needs; all TCP state stays in the Conn inside the stack.
func newStreamConn(s *Stack, c *Conn) *StreamConn {
	sc := &StreamConn{
		stack:  s,
		tuple:  c.tuple,
		local:  &net.TCPAddr{IP: append(net.IP(nil), s.ourIP...), Port: int(c.localPort)},
		remote: &net.TCPAddr{IP: append(net.IP(nil), c.remoteIP...), Port: int(c.remotePort)},
	}
	sc.cond = sync.NewCond(&sc.mu)
	return sc
}

// LocalAddr returns our IP and the listening port.
func (c *StreamConn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the peer's IP and port.
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }

// Read blocks until received bytes are available, then copies as many as
// fit into p. Once the peer has sent FIN (or the connection is reset or
// closed) and the buffer is drained, Read returns io.EOF. Buffered data
// is still returned after the peer's FIN, so nothing is lost at close.
func (c *StreamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A loop, not an if: condition variables can wake up without the
	// condition being true.
	for len(c.rbuf) == 0 && !c.rClosed && !c.dead {
		c.cond.Wait()
	}
	if len(c.rbuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write sends p to the peer, cut into segments of at most MaxSegPayload
// bytes. It returns as soon as each segment has been handed to the stack
// (and queued for retransmission), not when the peer acknowledges it.
// There is no send buffer and no flow control: Write never waits for the
// peer's window.
func (c *StreamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.wClosed || c.dead {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxSegPayload {
			n = MaxSegPayload
		}
		// Each chunk becomes one PSH+ACK segment. If the connection has
		// left ESTABLISHED, the error stops the loop and we report how
		// much was sent.
		if err := c.stack.writeStream(c.tuple, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close shuts both directions locally and asks the stack to send our FIN.
// From ESTABLISHED that is an active close (FIN_WAIT_1); from CLOSE_WAIT
// it completes a passive close (LAST_ACK). A blocked Read wakes and
// returns io.EOF. Closing a torn-down connection is a no-op.
func (c *StreamConn) Close() error {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return nil
	}
	c.wClosed = true
	c.rClosed = true
	c.cond.Broadcast()
	// Release our lock before taking the stack lock, to keep the lock
	// order Stack.mu then StreamConn.mu.
	c.mu.Unlock()
	return c.stack.closeStream(c.tuple)
}

// SetDeadline sets only the read deadline, which is itself not
// implemented (see SetReadDeadline).
func (c *StreamConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline is a no-op that exists to satisfy net.Conn. Reads
// never time out.
func (c *StreamConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a no-op that exists to satisfy net.Conn. Writes do
// not block, so there is nothing to time out.
func (c *StreamConn) SetWriteDeadline(time.Time) error { return nil }

// deliver appends in-order TCP payload for Read (called under stack lock).
// The stack has already advanced rcvNxt and will ACK these bytes, so
// they must not be dropped here unless the reader has gone away.
func (c *StreamConn) deliver(b []byte) {
	if len(b) == 0 {
		return
	}
	c.mu.Lock()
	// After a local Close nobody will Read, so the bytes are discarded.
	if !c.rClosed && !c.dead {
		c.rbuf = append(c.rbuf, b...)
		// There is at most one meaningful reader, so waking one is enough.
		c.cond.Signal()
	}
	c.mu.Unlock()
}

// peerClosed records the peer's FIN: no more bytes will arrive. Readers
// drain what is buffered and then get io.EOF. TCP would still let us send
// in CLOSE_WAIT, but writeStream only accepts ESTABLISHED, so Writes
// from here on fail. Called under the stack lock.
func (c *StreamConn) peerClosed() {
	c.mu.Lock()
	c.rClosed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

// teardown marks the connection as gone (fully closed or reset) and wakes
// every blocked Read. Further Writes fail with net.ErrClosed. Called under
// the stack lock from destroyLocked.
func (c *StreamConn) teardown() {
	c.mu.Lock()
	c.dead = true
	c.rClosed = true
	c.wClosed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}
