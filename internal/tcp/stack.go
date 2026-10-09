// Package tcp is the transport layer of the stack: a small TCP.
//
// Below it, the IPv4 layer hands us segments (Decode turns an IPv4 payload
// into a Segment, and Stack.Handle processes it). Above it, applications
// see what a kernel socket gives them: Stack.Listen returns a net.Listener
// (Listener), Stack.Dial connects out, and each connection is a net.Conn
// (StreamConn).
//
// It does the three-way handshake both ways, in-order delivery, ACKs,
// timer-based retransmission, and both close sequences. It deliberately
// leaves out: congestion control, send-side flow control, SACK, window
// scaling and all other options (so no MSS either), out-of-order
// reassembly, TIME_WAIT, and RTT estimation.
package tcp

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"syscall"
	"time"
)

// State is a TCP connection state (RFC 9293 section 3.3.2):
//
//	LISTEN (per port)              Dial
//	    |                            |
//	    | recv SYN,                  | send SYN
//	    | send SYN+ACK               v
//	    v                        SYN_SENT
//	SYN_RECEIVED                     |
//	    |                            | recv SYN+ACK,
//	    | recv ACK of our SYN        | send ACK
//	    +-----------+----------------+
//	                v
//	           ESTABLISHED
//	                |
//	    +-----------+------------+
//	    |                        |
//	    | recv FIN,              | app closes,
//	    | send ACK               | send FIN
//	    v                        v
//	CLOSE_WAIT               FIN_WAIT_1
//	    |                        |
//	    | app closes,            | recv ACK of our FIN
//	    | send FIN               v
//	    v                    FIN_WAIT_2
//	 LAST_ACK                    |
//	    |                        | recv FIN, send ACK
//	    | recv ACK of our FIN    |
//	    v                        v
//	  CLOSED                   CLOSED
//
//	peer closes first        we close first
//
// Two shortcuts leave FIN_WAIT_1 when the peer's FIN arrives there (we
// always ACK it):
//
//	FIN_WAIT_1 --recv FIN that also ACKs our FIN--> CLOSED
//	FIN_WAIT_1 --recv FIN, ours not yet ACKed-----> LAST_ACK  (simultaneous close)
//
// Differences from the full RFC diagram: no simultaneous open (a bare
// SYN in SYN_SENT is ignored), no TIME_WAIT (the connection is forgotten as soon as the
// final ACK is sent), and no separate CLOSING state (a simultaneous close
// reuses LAST_ACK, which waits for the same thing: the ACK of our FIN).
// A RST in any state jumps straight to CLOSED.
type State int

// The connection states. StateListen is listed for completeness, but
// listening is tracked per port in Stack.listen; a Conn is created
// directly in StateSynReceived or StateSynSent.
const (
	StateListen  State = iota
	StateSynSent       // Dial sent our SYN; waiting for SYN+ACK
	StateSynReceived
	StateEstablished
	StateCloseWait // peer sent FIN; waiting for our app to close
	StateLastAck   // we sent our FIN after the peer's; waiting for its ACK
	StateFinWait1  // we sent FIN first (e.g. HTTP Connection: close)
	StateFinWait2  // our FIN is ACKed; waiting for the peer's FIN
	StateClosed
)

// String returns the conventional RFC name of the state, as used in logs.
func (s State) String() string {
	switch s {
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECEIVED"
	case StateEstablished:
		return "ESTABLISHED"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateLastAck:
		return "LAST_ACK"
	case StateFinWait1:
		return "FIN_WAIT_1"
	case StateFinWait2:
		return "FIN_WAIT_2"
	case StateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("State(%d)", s)
	}
}

// fourTuple identifies a connection. A TCP connection is uniquely named by
// (remote IP, remote port, local IP, local port). We only have one local
// IP, so three fields are enough. The IP is stored as a string so the
// struct can be a map key.
type fourTuple struct {
	remoteIP   string
	remotePort uint16
	localPort  uint16
}

// outstanding is a sent segment that the peer has not yet acknowledged.
// It is kept so Tick can resend it byte-for-byte if the ACK does not
// arrive in time. Only segments that consume sequence space (data, SYN,
// FIN) are tracked; a bare ACK is never retransmitted.
type outstanding struct {
	seg       Segment
	dstIP     net.IP
	dstMAC    net.HardwareAddr
	firstSent time.Time
	lastSent  time.Time // drives the retransmission timer
	retries   int
}

// Emitter is TCP's way down to IPv4/Ethernet. The stack package
// implements it. SendTCP encodes a segment, wraps it in an IPv4 packet and
// an Ethernet frame, and writes it to the TAP device. Resolve finds the
// MAC to send to when we start a connection and have no frame to reply to.
type Emitter interface {
	SendTCP(dstMAC net.HardwareAddr, dstIP net.IP, seg Segment) error
	Resolve(ctx context.Context, ip net.IP) (net.HardwareAddr, error)
}

// Stack owns the listening ports and all live connections.
//
// Locking: mu protects every field of Stack and every field of every Conn
// (state, sequence numbers, outq). All input (Handle), timers (Tick) and
// StreamConn writes and closes take mu, so the state machine runs one
// segment at a time. StreamConn has its own lock for its read buffer; the
// order is always Stack.mu first, then StreamConn.mu.
type Stack struct {
	mu       sync.Mutex
	ourIP    net.IP
	listen   map[uint16]*Listener // ports in LISTEN
	conns    map[fourTuple]*Conn
	emit     Emitter
	iss      uint32 // initial sequence number for the next connection
	nextPort uint32 // where Dial starts looking for a free ephemeral port
	rto      time.Duration
	maxRetry int
	now      func() time.Time // replaceable clock, for tests
	log      *log.Logger
}

// Conn is the per-connection state, what RFC 9293 calls the Transmission
// Control Block (TCB).
//
// The sequence variables use the RFC names:
//
//	sndUna  oldest byte we sent that is not yet acknowledged ("send unacknowledged")
//	sndNxt  sequence number of the next byte we will send
//	rcvNxt  sequence number of the next byte we expect from the peer;
//	        this is what we put in the Ack field
//
// Everything in [sndUna, sndNxt) is "in flight" and sits in outq.
type Conn struct {
	tuple                 fourTuple
	state                 State
	remoteIP              net.IP
	remoteMAC             net.HardwareAddr
	localPort, remotePort uint16

	rcvNxt uint32
	sndUna uint32
	sndNxt uint32
	sndWnd uint16 // peer's advertised window; recorded but not enforced when sending
	rcvWnd uint16 // window we advertise; fixed, not tied to buffer space

	outq   []outstanding // unacked segments, oldest first
	stream *StreamConn   // the app's net.Conn; set at ESTABLISHED

	dialDone chan error // Dial only: the handshake's outcome, sent once
}

// NewStack creates a TCP layer for ourIP. Segments go out through emit.
// If logger is nil, the default logger is used. Nothing is accepted until
// Listen opens a port.
func NewStack(ourIP net.IP, emit Emitter, logger *log.Logger) *Stack {
	if logger == nil {
		logger = log.Default()
	}
	return &Stack{
		ourIP:  ourIP.To4(),
		listen: make(map[uint16]*Listener),
		conns:  make(map[fourTuple]*Conn),
		emit:   emit,
		// A fixed, predictable starting ISN keeps logs and demos
		// readable. Real stacks pick ISNs from a clock plus a secret hash
		// (RFC 9293 section 3.4.1, RFC 6528) so attackers cannot guess them.
		iss: 1000,
		// A fixed retransmission timeout. RFC 6298 computes it from
		// measured round-trip times and doubles it on each retry; we do
		// neither.
		rto:      500 * time.Millisecond,
		maxRetry: 5,
		// Start the ephemeral port search somewhere random (RFC 6056).
		// Starting at 49152 every run would reuse the same 4-tuple each
		// time, and a NAT that still remembers the last run's flow
		// silently drops the new one.
		nextPort: rand.Uint32(),
		now:      time.Now,
		log:      logger,
	}
}

// Handle is the entry point from IPv4: it processes one incoming segment
// from srcIP (whose Ethernet address is srcMAC).
//
// The whole state machine runs under s.mu. If this segment completed a
// handshake, the new StreamConn is pushed to its port's Listener on a new
// goroutine after the lock is released, so a slow Accept never stalls
// the input path.
func (s *Stack) Handle(srcMAC net.HardwareAddr, srcIP net.IP, seg Segment) error {
	s.mu.Lock()
	var accepted *StreamConn
	err := s.handleLocked(srcMAC, srcIP, seg, &accepted)
	var ln *Listener
	if accepted != nil {
		ln = s.listen[seg.DstPort]
	}
	s.mu.Unlock()
	if accepted != nil {
		if ln != nil {
			go ln.push(accepted)
		} else {
			// The Listener closed during the handshake.
			go accepted.Close()
		}
	}
	return err
}

// handleLocked finds the connection a segment belongs to, or decides
// whether it may start a new one. Caller holds s.mu.
func (s *Stack) handleLocked(srcMAC net.HardwareAddr, srcIP net.IP, seg Segment, accepted **StreamConn) error {
	key := fourTuple{
		remoteIP:   srcIP.String(),
		remotePort: seg.SrcPort,
		localPort:  seg.DstPort,
	}

	c, ok := s.conns[key]
	if !ok {
		// A RST for a connection we already dropped needs no answer, and
		// answering it with a RST could ping-pong forever.
		if seg.Has(FlagRST) {
			return nil
		}
		// No connection yet. Nobody on this port: RST tells the peer
		// "connection refused" instead of letting it time out.
		if _, listening := s.listen[seg.DstPort]; !listening {
			return s.sendRSTLocked(srcMAC, srcIP, seg)
		}
		// A listening port only accepts a bare SYN. Anything else (a
		// stray ACK, data for a connection we already forgot) gets a RST.
		if !seg.Has(FlagSYN) || seg.Has(FlagACK) {
			return s.sendRSTLocked(srcMAC, srcIP, seg)
		}
		return s.acceptSYNLocked(srcMAC, srcIP, seg, key)
	}

	// Remember the latest source MAC so replies follow the peer if its
	// Ethernet address changes.
	c.remoteMAC = append(net.HardwareAddr(nil), srcMAC...)
	return s.driveConnLocked(c, seg, accepted)
}

// acceptSYNLocked handles step one of the three-way handshake. It creates
// the connection in SYN_RECEIVED and replies with SYN+ACK (step two):
//
//	peer                         us
//	 | --- SYN seq=x ----------->  |   (this function)
//	 | <-- SYN+ACK seq=y ack=x+1-  |
//	 | --- ACK ack=y+1 --------->  |   (driveConnLocked, SYN_RECEIVED)
//
// Caller holds s.mu.
func (s *Stack) acceptSYNLocked(srcMAC net.HardwareAddr, srcIP net.IP, seg Segment, key fourTuple) error {
	// Take this connection's ISN and step the counter by a large gap so
	// sequence ranges of consecutive connections are easy to tell apart
	// in logs.
	iss := s.iss
	s.iss += 100000

	c := &Conn{
		tuple:      key,
		state:      StateSynReceived,
		remoteIP:   append(net.IP(nil), srcIP.To4()...),
		remoteMAC:  append(net.HardwareAddr(nil), srcMAC...),
		localPort:  seg.DstPort,
		remotePort: seg.SrcPort,
		// The peer's SYN consumes one sequence number, so its first data
		// byte will be seg.Seq+1. Acking that number acknowledges the SYN.
		rcvNxt: seg.Seq + 1,
		// Nothing sent yet: both send pointers start at our ISN.
		sndUna: iss,
		sndNxt: iss,
		sndWnd: seg.Window,
		// Advertise the largest window that fits in 16 bits without the
		// window-scale option.
		rcvWnd: 65535,
	}
	s.conns[key] = c
	s.log.Printf("tcp: %s:%d -> :%d SYN seq=%d → SYN_RECEIVED", srcIP, seg.SrcPort, seg.DstPort, seg.Seq)

	synAck := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sndNxt,
		Ack:     c.rcvNxt,
		Flags:   FlagSYN | FlagACK,
		Window:  c.rcvWnd,
	}
	// Our SYN also consumes one sequence number, so our first data byte
	// will be ISN+1, and the peer's handshake ACK must say ack=ISN+1.
	// sendCtrlLocked is bypassed here because it would bump sndNxt from
	// the flags itself; the SYN+ACK is still tracked for retransmission.
	c.sndNxt++
	return s.sendTrackedLocked(c, synAck)
}

// driveConnLocked runs one segment through the state machine of an
// existing connection. Caller holds s.mu. If the segment completes the
// handshake, *accepted is set so Handle can pass it to the Listener after
// unlocking.
//
// Simplification: incoming sequence numbers are checked only for exact
// equality with rcvNxt, not against the full receive window as RFC 9293
// section 3.10.7.4 describes.
func (s *Stack) driveConnLocked(c *Conn, seg Segment, accepted **StreamConn) error {
	// A reset aborts the connection immediately in every state. The RST's
	// sequence number is not checked.
	if seg.Has(FlagRST) {
		if c.state == StateSynSent {
			// A RST that acks our SYN means nobody listens there. Any
			// other RST could be stale and is ignored.
			if seg.Has(FlagACK) && seg.Ack == c.sndNxt {
				s.log.Printf("tcp: conn %v refused", c.tuple)
				s.failDialLocked(c, syscall.ECONNREFUSED)
			}
			return nil
		}
		s.log.Printf("tcp: conn %v RST → CLOSED", c.tuple)
		s.destroyLocked(c)
		return nil
	}

	// Any ACK may free segments from the retransmission queue,
	// whatever state we are in.
	if seg.Has(FlagACK) {
		s.ackOutstandingLocked(c, seg.Ack)
	}
	// Track the peer's advertised window. A zero window is ignored, and
	// the value is not used to limit sending anyway (no flow control on
	// our send side).
	if seg.Window > 0 {
		c.sndWnd = seg.Window
	}

	switch c.state {
	case StateSynSent:
		// Step two of our handshake: SYN+ACK that acks our SYN. Our ACK
		// back is step three, and Dial returns.
		if seg.Has(FlagSYN) && seg.Has(FlagACK) && seg.Ack == c.sndNxt {
			c.rcvNxt = seg.Seq + 1
			c.state = StateEstablished
			c.stream = newStreamConn(s, c)
			s.log.Printf("tcp: conn %v ESTABLISHED (dialed)", c.tuple)
			err := s.sendCtrlLocked(c, FlagACK, nil)
			c.dialDone <- nil
			return err
		}
		return nil

	case StateSynReceived:
		// Step three of the handshake: a plain ACK that acknowledges our
		// SYN, i.e. ack == ISN+1 == sndNxt.
		if seg.Has(FlagACK) && !seg.Has(FlagSYN) && seg.Ack == c.sndNxt {
			c.state = StateEstablished
			c.sndUna = seg.Ack
			s.log.Printf("tcp: conn %v ESTABLISHED", c.tuple)
			// This is the moment Accept returns.
			c.stream = newStreamConn(s, c)
			*accepted = c.stream
		}
		// The handshake ACK may already carry the first request bytes.
		if c.state == StateEstablished && len(seg.Payload) > 0 {
			return s.recvDataLocked(c, seg)
		}
		return nil

	case StateEstablished:
		// Passive close: the peer is done sending.
		if seg.Has(FlagFIN) {
			// Only accept the FIN once all earlier bytes have arrived;
			// otherwise drop it and let the peer retransmit.
			if seg.Seq != c.rcvNxt {
				return nil
			}
			// The FIN consumes one sequence number, so acking seq+1
			// acknowledges it. Any payload in the same segment is not
			// delivered or counted here.
			c.rcvNxt = seg.Seq + 1
			// Read returns EOF once the buffer drains. Our FIN waits for
			// the app's Close.
			c.stream.peerClosed()
			c.state = StateCloseWait
			s.log.Printf("tcp: conn %v CLOSE_WAIT", c.tuple)
			return s.sendCtrlLocked(c, FlagACK, nil)
		}
		return s.recvDataLocked(c, seg)

	case StateFinWait1:
		// We sent FIN first. The peer's ACK of our FIN (ack == sndNxt,
		// because the FIN was the last thing we sent) moves us on.
		if seg.Has(FlagACK) && seg.Ack == c.sndNxt {
			c.state = StateFinWait2
			s.log.Printf("tcp: conn %v FIN_WAIT_2", c.tuple)
		}
		// The peer's FIN may arrive in the same segment as that ACK (the
		// common FIN+ACK reply), or on its own. Data in this state is not
		// delivered.
		if seg.Has(FlagFIN) && seg.Seq == c.rcvNxt {
			c.rcvNxt = seg.Seq + 1
			if err := s.sendCtrlLocked(c, FlagACK, nil); err != nil {
				return err
			}
			// Both FINs sent and acknowledged: done. With no TIME_WAIT
			// the connection is forgotten right after our last ACK.
			if c.state == StateFinWait2 || (seg.Has(FlagACK) && seg.Ack == c.sndNxt) {
				s.log.Printf("tcp: conn %v CLOSED", c.tuple)
				s.destroyLocked(c)
			} else {
				// Simultaneous close: the peer's FIN crossed ours before
				// it acked ours. RFC 9293 calls this CLOSING; we reuse
				// LAST_ACK because both wait for the ACK of our FIN.
				c.state = StateLastAck
				s.log.Printf("tcp: conn %v LAST_ACK (closing)", c.tuple)
			}
		}
		return nil

	case StateFinWait2:
		// Our FIN is acked; we only wait for the peer's FIN. Data in this
		// state is not delivered.
		if seg.Has(FlagFIN) && seg.Seq == c.rcvNxt {
			c.rcvNxt = seg.Seq + 1
			if err := s.sendCtrlLocked(c, FlagACK, nil); err != nil {
				return err
			}
			// A full stack would enter TIME_WAIT here to absorb a
			// retransmitted FIN if our ACK is lost. We drop the state now.
			s.log.Printf("tcp: conn %v CLOSED", c.tuple)
			s.destroyLocked(c)
		}
		return nil

	case StateLastAck:
		// Last step of either close path: the peer acks our FIN.
		if seg.Has(FlagACK) && seg.Ack == c.sndNxt {
			s.log.Printf("tcp: conn %v CLOSED", c.tuple)
			s.destroyLocked(c)
		}
		return nil

	default:
		// CLOSE_WAIT: the peer has finished sending, so there is nothing
		// to receive; we are waiting for our own app to call Close.
		return nil
	}
}

// recvDataLocked accepts payload bytes in ESTABLISHED (or on the handshake
// ACK) and queues them for StreamConn.Read. Caller holds s.mu.
func (s *Stack) recvDataLocked(c *Conn, seg Segment) error {
	if len(seg.Payload) == 0 {
		return nil
	}
	// In-order only. A segment that does not start exactly at rcvNxt
	// (a gap, a duplicate, or a partial overlap) is dropped, not buffered.
	// We re-send an ACK for rcvNxt, which tells the peer where the hole
	// is; its retransmission timer will fill it in.
	if seg.Seq != c.rcvNxt {
		s.log.Printf("tcp: out-of-order seq=%d want=%d — ACK only", seg.Seq, c.rcvNxt)
		return s.sendCtrlLocked(c, FlagACK, nil)
	}
	// Each payload byte consumes one sequence number.
	c.rcvNxt += uint32(len(seg.Payload))
	s.log.Printf("tcp: recv %d bytes from %v: %q", len(seg.Payload), c.tuple, truncate(seg.Payload, 64))

	// Queue the bytes for Read and ACK them now. Replies come later,
	// whenever the app calls Write.
	c.stream.deliver(seg.Payload)
	return s.sendCtrlLocked(c, FlagACK, nil)
}

// destroyLocked forgets a connection: wakes any StreamConn reader or
// writer and removes the TCB. Unacked segments are discarded with it.
// Caller holds s.mu.
func (s *Stack) destroyLocked(c *Conn) {
	if c.stream != nil {
		c.stream.teardown()
	}
	delete(s.conns, c.tuple)
}

// writeStream sends one chunk of StreamConn.Write data as a single
// PSH+ACK segment. The caller has already cut it to at most
// MaxSegPayload bytes. Sending is only allowed in ESTABLISHED.
func (s *Stack) writeStream(tuple fourTuple, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.conns[tuple]
	if !ok || c.state != StateEstablished {
		return net.ErrClosed
	}
	// Copy: the segment lives on in outq for retransmission, and the
	// caller may reuse its buffer after Write returns.
	return s.sendCtrlLocked(c, FlagACK|FlagPSH, append([]byte(nil), payload...))
}

// closeStream sends our FIN when a stream app calls Close. Which close
// path we take depends on who finished first.
func (s *Stack) closeStream(tuple fourTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.conns[tuple]
	if !ok {
		return nil
	}
	switch c.state {
	case StateEstablished:
		// We close first (active close).
		c.state = StateFinWait1
		s.log.Printf("tcp: conn %v FIN_WAIT_1 (stream close)", c.tuple)
		return s.sendCtrlLocked(c, FlagFIN|FlagACK, nil)
	case StateCloseWait:
		// The peer already closed; this is our half (passive close).
		c.state = StateLastAck
		return s.sendCtrlLocked(c, FlagFIN|FlagACK, nil)
	default:
		// Already closing: a second Close is a no-op.
		return nil
	}
}

// sendCtrlLocked builds and sends a segment at the current send position,
// acking everything received so far. It advances sndNxt by the sequence
// space the segment uses, and queues it for retransmission if that space
// is non-zero. Caller holds s.mu.
func (s *Stack) sendCtrlLocked(c *Conn, flags uint8, payload []byte) error {
	seg := Segment{
		SrcPort: c.localPort,
		DstPort: c.remotePort,
		Seq:     c.sndNxt,
		Ack:     c.rcvNxt,
		Flags:   flags,
		Window:  c.rcvWnd,
		Payload: payload,
	}
	// Sequence space used: one per payload byte, plus one each for SYN
	// and FIN. A bare ACK uses none, so it can be sent again at the same
	// seq any number of times.
	n := uint32(len(payload))
	if flags&FlagSYN != 0 || flags&FlagFIN != 0 {
		n++
	}
	c.sndNxt += n
	// Only segments the peer must acknowledge go in the retransmission
	// queue. ACKs are never acked, so a lost ACK is repaired by the peer
	// retransmitting its data.
	if n > 0 {
		return s.sendTrackedLocked(c, seg)
	}
	return s.emit.SendTCP(c.remoteMAC, c.remoteIP, seg)
}

// sendTrackedLocked sends seg and appends it to the connection's
// retransmission queue, starting its timer. Caller holds s.mu.
//
// No congestion window and no check of the peer's window: every segment
// is sent immediately.
func (s *Stack) sendTrackedLocked(c *Conn, seg Segment) error {
	now := s.now()
	c.outq = append(c.outq, outstanding{
		seg:       seg,
		dstIP:     append(net.IP(nil), c.remoteIP...),
		dstMAC:    append(net.HardwareAddr(nil), c.remoteMAC...),
		firstSent: now,
		lastSent:  now,
	})
	s.log.Printf("tcp: send %s seq=%d ack=%d len=%d → %s:%d",
		FlagsString(seg.Flags), seg.Seq, seg.Ack, len(seg.Payload), c.remoteIP, c.remotePort)
	return s.emit.SendTCP(c.remoteMAC, c.remoteIP, seg)
}

// ackOutstandingLocked processes a cumulative ACK. TCP's Ack field means
// "I have every byte before this number", so every queued segment whose
// last sequence number is below ack is done and leaves the queue. A
// segment only partly covered stays whole and may be resent whole.
// Caller holds s.mu.
//
// Simplification: comparisons are plain integer >=, so they do not
// handle 32-bit sequence number wraparound.
func (s *Stack) ackOutstandingLocked(c *Conn, ack uint32) {
	n := 0
	for _, o := range c.outq {
		// end is the sequence number just past this segment; SYN and
		// FIN each occupy one extra number.
		end := o.seg.Seq + uint32(len(o.seg.Payload))
		if o.seg.Has(FlagSYN) || o.seg.Has(FlagFIN) {
			end++
		}
		if ack >= end {
			n++
			continue
		}
		// The queue is in send order, so the first uncovered segment
		// means all later ones are uncovered too.
		break
	}
	if n > 0 {
		c.outq = c.outq[n:]
		c.sndUna = ack
	}
}

// sendRSTLocked answers a segment that belongs to no connection with a
// reset. The RST must carry numbers the peer will accept (RFC 9293
// section 3.10.7.1):
//
//   - If the incoming segment had an ACK, the RST uses seq = that ack
//     value, which is exactly where the peer thinks our sequence is.
//   - Otherwise the RST uses seq = 0 with ACK set, acking everything in
//     the offending segment (payload plus SYN/FIN) so the peer can match
//     it to what it sent.
//
// Caller holds s.mu.
func (s *Stack) sendRSTLocked(dstMAC net.HardwareAddr, dstIP net.IP, in Segment) error {
	seg := Segment{
		SrcPort: in.DstPort,
		DstPort: in.SrcPort,
		Flags:   FlagRST | FlagACK,
		Window:  0,
	}
	if in.Has(FlagACK) {
		seg.Seq = in.Ack
		seg.Flags = FlagRST
	} else {
		seg.Ack = in.Seq + uint32(len(in.Payload))
		if in.Has(FlagSYN) || in.Has(FlagFIN) {
			seg.Ack++
		}
		seg.Seq = 0
		seg.Flags = FlagRST | FlagACK
	}
	// RSTs are never retransmitted or tracked: if one is lost, the peer
	// will send again and get another.
	s.log.Printf("tcp: RST → %s:%d", dstIP, in.SrcPort)
	return s.emit.SendTCP(dstMAC, dstIP, seg)
}

// Tick retransmits timed-out unacked segments. Call periodically (the
// main program calls it every 100 ms).
//
// Every queued segment has its own timer: if it has gone s.rto without
// an ACK since it was last sent, it is sent again unchanged. The timeout
// stays fixed (no exponential backoff). After maxRetry resends the
// segment is no longer retransmitted, but the connection is not closed
// and the segment stays in the queue. The exception is a Dial's SYN: then
// Dial fails with a timeout.
func (s *Stack) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var timedOut []*Conn
	defer func() {
		for _, c := range timedOut {
			s.failDialLocked(c, syscall.ETIMEDOUT)
		}
	}()
	for _, c := range s.conns {
		for i := range c.outq {
			o := &c.outq[i]
			if now.Sub(o.lastSent) < s.rto {
				continue
			}
			if o.retries >= s.maxRetry {
				s.log.Printf("tcp: give up retransmit on %v after %d tries", c.tuple, o.retries)
				if c.state == StateSynSent {
					timedOut = append(timedOut, c)
					break
				}
				continue
			}
			o.retries++
			o.lastSent = now
			s.log.Printf("tcp: RETRANSMIT #%d %s seq=%d len=%d → %s:%d",
				o.retries, FlagsString(o.seg.Flags), o.seg.Seq, len(o.seg.Payload), c.remoteIP, c.remotePort)
			// The resent segment keeps its original Ack and Window
			// values. Send errors are ignored; the next tick tries again.
			_ = s.emit.SendTCP(o.dstMAC, o.dstIP, o.seg)
		}
	}
}

// truncate returns b as a string, cut to n bytes with an ellipsis, for
// logging payloads.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
