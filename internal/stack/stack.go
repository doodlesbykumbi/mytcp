// Package stack is the dispatcher that ties the protocol layers together.
//
// It takes raw Ethernet frames from a TAP-like device, peels them one layer
// at a time (Ethernet, then ARP or IPv4, then ICMP, TCP or UDP), and hands
// TCP segments up to the tcp package. On the way down it does the reverse:
// wraps TCP segments, UDP datagrams and ICMP replies in IPv4 and Ethernet
// and writes them out.
//
// Replies go straight back to the MAC address the request came from. New
// connections (Dial) pick a next hop, on-link or the one gateway, and find
// its MAC with ARP (neigh.go). It deliberately leaves out a routing table,
// ARP cache expiry, IP fragmentation, IPv6, UDP beyond what DNS needs, and
// checksum verification on input.
package stack

import (
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/capture"
	"github.com/doodlesbykumbi/mytcp/internal/dump"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
	"github.com/doodlesbykumbi/mytcp/internal/icmp"
	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/tcp"
)

// NetIF is a TAP-like frame I/O device. Each Read returns exactly one
// Ethernet frame and each Write sends exactly one. In production this is
// a *tap.Device; tests can plug in a fake.
type NetIF interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Name() string
}

// Config holds the identity we claim on the wire and how much to record.
// Applications open TCP ports afterwards with TCP().Listen.
type Config struct {
	MAC      net.HardwareAddr  // our Ethernet address; frames to any other unicast MAC are dropped
	IP       net.IP            // our IPv4 address; ARP and IPv4 only answer for this one
	Subnet   *net.IPNet        // hosts reached directly; nil = everything is on-link
	Gateway  net.IP            // next hop for anything outside Subnet; nil = no route out
	ARPRetry time.Duration     // wait between ARP requests when dialing; 0 = 1s
	DNS      net.IP            // resolver LookupIPv4 asks; nil = names cannot be dialed
	Dump     bool              // print every RX and TX frame as a layered decode
	DumpOut  io.Writer         // where Dump output goes; nil disables dumping
	Capture  *capture.Recorder // optional disk capture
	Logger   *log.Logger
}

// Stack is the userspace L2–L4 handler. It owns the TCP layer and is also
// the TCP layer's way back down to the wire (it implements tcp.Emitter).
//
// Concurrency: Stack has no lock of its own. HandleFrame is called from a
// single frame-reading goroutine. Tick runs on a timer goroutine, and TLS
// apps write from one goroutine per connection. The tcp.Stack mutex
// serializes everything TCP sends, but ARP and ICMP replies are sent from
// the reader goroutine outside that lock. So the IPv4 ID counter is atomic,
// and wireMu keeps dumps and NIC writes from different goroutines apart.
type Stack struct {
	cfg      Config
	nif      NetIF
	tcp      *tcp.Stack
	log      *log.Logger
	ipID     atomic.Uint32 // IPv4 Identification counter; the low 16 bits go on the wire
	wireMu   sync.Mutex    // held while dumping a frame or writing one to the NIC
	neigh    *neighbors    // ARP cache, for connections we start
	arpRetry time.Duration
	udp      udpPorts // bound UDP ports (DNS)
}

// New builds a Stack on top of nif. No TCP port is open yet.
func New(nif NetIF, cfg Config) *Stack {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	// The TCP layer gets s as its Emitter: when TCP wants to send a
	// segment, it calls s.SendTCP, which wraps it in IPv4 and Ethernet.
	s := &Stack{cfg: cfg, nif: nif, log: logger, neigh: newNeighbors(), arpRetry: cfg.ARPRetry}
	s.udp.bound = make(map[uint16]*UDPPort)
	s.udp.next = rand.Uint32() // random first ephemeral port, as in tcp.NewStack
	if s.arpRetry == 0 {
		s.arpRetry = time.Second
	}
	s.tcp = tcp.NewStack(cfg.IP, s, logger)
	return s
}

// TCP returns the userspace TCP layer. Apps get a net.Listener from
// TCP().Listen(port).
func (s *Stack) TCP() *tcp.Stack { return s.tcp }

// SendTCP implements tcp.Emitter. It serializes seg (the TCP checksum needs
// both IP addresses, which is why they are passed in) and sends it as an
// IPv4 packet with protocol number 6.
func (s *Stack) SendTCP(dstMAC net.HardwareAddr, dstIP net.IP, seg tcp.Segment) error {
	payload := seg.Encode(s.cfg.IP, dstIP)
	return s.sendIPv4(dstMAC, dstIP, ip4.ProtoTCP, payload)
}

// sendIPv4 wraps payload in an IPv4 header, then in an Ethernet frame
// addressed to dstMAC, and writes it out. The caller already knows the
// next hop's MAC: the MAC a request arrived from, or one Resolve found.
func (s *Stack) sendIPv4(dstMAC net.HardwareAddr, dstIP net.IP, proto uint8, payload []byte) error {
	// The ID only matters for fragment reassembly, but it should still
	// change per packet so captures are easy to follow.
	pkt := ip4.Packet{
		ID:      uint16(s.ipID.Add(1)),
		TTL:     64, // a common default hop limit
		Proto:   proto,
		Src:     s.cfg.IP,
		Dst:     dstIP,
		Payload: payload,
	}
	frame := eth.Frame{
		Dst:     dstMAC,
		Src:     s.cfg.MAC,
		Type:    eth.TypeIPv4,
		Payload: pkt.Encode(),
	}
	return s.writeFrame(frame)
}

// writeFrame is the single exit point to the wire. Every outgoing frame
// passes through here, so this is where TX frames are dumped and captured.
func (s *Stack) writeFrame(f eth.Frame) error {
	b := f.Encode()
	s.wireMu.Lock()
	defer s.wireMu.Unlock()
	if s.cfg.Dump && s.cfg.DumpOut != nil {
		dump.Frame(s.cfg.DumpOut, ">>> TX", b)
	}
	// A failed capture write is logged but never stops the packet.
	if s.cfg.Capture != nil {
		if err := s.cfg.Capture.Write(capture.TX, b); err != nil {
			s.log.Printf("capture: %v", err)
		}
	}
	_, err := s.nif.Write(b)
	return err
}

// Tick runs TCP retransmit checks. The caller drives it from a timer;
// the stack itself starts no goroutines.
func (s *Stack) Tick() { s.tcp.Tick() }

// HandleFrame processes one Ethernet frame. It is the root of the
// demultiplexing tree: at each layer, one header field names the next
// layer, and the frame is handed to that layer's handler.
//
//	Ethernet frame
//	 └─ EtherType (bytes 12-13 of the frame)
//	     ├─ 0x0806 ARP   → handleARP: answer "who has our IP?", learn replies
//	     └─ 0x0800 IPv4  → handleIPv4
//	         └─ Protocol (byte 9 of the IPv4 header)
//	             ├─ 1 ICMP → handleICMP: answer ping
//	             ├─ 6 TCP  → tcp.Stack.Handle → StreamConn → Listener
//	             └─ 17 UDP → handleUDP → UDPPort (DNS answers)
//
// Anything else is logged and dropped. Decode errors are returned to the
// caller, which logs them; they never stop the stack.
func (s *Stack) HandleFrame(b []byte) error {
	// Record the frame exactly as it arrived, before any filtering, so
	// the dump and capture show everything the TAP delivered.
	if s.cfg.Dump && s.cfg.DumpOut != nil {
		s.wireMu.Lock()
		dump.Frame(s.cfg.DumpOut, "<<< RX", b)
		s.wireMu.Unlock()
	}
	if s.cfg.Capture != nil {
		if err := s.cfg.Capture.Write(capture.RX, b); err != nil {
			s.log.Printf("capture: %v", err)
		}
	}

	f, err := eth.Decode(b)
	if err != nil {
		return err
	}

	// Accept unicast to us or broadcast. This is what a real network card
	// does in hardware. ARP requests arrive as broadcast because the
	// sender does not know our MAC yet.
	if !isBroadcast(f.Dst) && !macEqual(f.Dst, s.cfg.MAC) {
		return nil
	}

	// The EtherType field decides the next layer.
	switch f.Type {
	case eth.TypeARP:
		return s.handleARP(f)
	case eth.TypeIPv4:
		return s.handleIPv4(f)
	default:
		// Usually IPv6 (0x86DD) chatter from the host kernel.
		s.log.Printf("eth: ignore type %s", eth.TypeName(f.Type))
		return nil
	}
}

// handleARP answers ARP requests for our IP address and learns from
// replies to our own requests. ARP is how the host turns "send to
// 10.0.0.2" into "send to MAC 02:00:00:00:00:02". Without our reply, the
// host never sends us any IP traffic at all.
func (s *Stack) handleARP(f eth.Frame) error {
	p, err := arp.Decode(f.Payload)
	if err != nil {
		return err
	}
	// Requests are broadcast to everyone; only the ones about us matter.
	if !p.TPA.Equal(s.cfg.IP) {
		return nil
	}
	// Either way the sender just told us its own address. RFC 826 learns
	// it from requests too, since the asker is about to talk to us.
	s.neigh.learn(p.SPA, p.SHA)
	if p.Op != arp.OpRequest {
		s.log.Printf("arp: %s is at %s", p.SPA, p.SHA)
		return nil
	}
	s.log.Printf("arp: who-has %s tell %s — reply", s.cfg.IP, p.SPA)
	reply := arp.ReplyFor(p, s.cfg.MAC, s.cfg.IP)
	// The reply is unicast straight back to the asker's MAC (the sender
	// hardware address from the request), not broadcast.
	out := eth.Frame{
		Dst:     p.SHA,
		Src:     s.cfg.MAC,
		Type:    eth.TypeARP,
		Payload: reply.Encode(),
	}
	return s.writeFrame(out)
}

// handleIPv4 unwraps an IPv4 packet addressed to us and dispatches on its
// Protocol field.
func (s *Stack) handleIPv4(f eth.Frame) error {
	pkt, err := ip4.Decode(f.Payload)
	if err != nil {
		return err
	}
	// We are a host, not a router: packets for other IPs are not forwarded.
	if !pkt.Dst.Equal(s.cfg.IP) {
		return nil
	}
	// The IPv4 Protocol field decides the next layer.
	switch pkt.Proto {
	case ip4.ProtoICMP:
		return s.handleICMP(f.Src, pkt)
	case ip4.ProtoTCP:
		seg, err := tcp.Decode(pkt.Payload)
		if err != nil {
			return err
		}
		s.log.Printf("tcp: %s:%d → :%d %s seq=%d ack=%d len=%d",
			pkt.Src, seg.SrcPort, seg.DstPort, tcp.FlagsString(seg.Flags), seg.Seq, seg.Ack, len(seg.Payload))
		// The Ethernet source MAC travels up with the segment so TCP
		// can address its replies without an ARP cache.
		return s.tcp.Handle(f.Src, pkt.Src, seg)
	case ip4.ProtoUDP:
		return s.handleUDP(pkt)
	default:
		s.log.Printf("ipv4: ignore proto %s from %s", ip4.ProtoName(pkt.Proto), pkt.Src)
		return nil
	}
}

// handleICMP answers ping. An echo reply carries the same identifier,
// sequence number, and payload as the request, which is how ping matches
// replies to requests and measures round-trip time.
func (s *Stack) handleICMP(srcMAC net.HardwareAddr, pkt ip4.Packet) error {
	echo, err := icmp.Decode(pkt.Payload)
	if err != nil {
		return err
	}
	// Only echo requests (type 8) get a reply; other ICMP messages are dropped.
	if echo.Type != icmp.TypeEcho {
		return nil
	}
	s.log.Printf("icmp: echo request id=%d seq=%d from %s — reply", echo.ID, echo.Seq, pkt.Src)
	reply := icmp.ReplyFrom(echo)
	return s.sendIPv4(srcMAC, pkt.Src, ip4.ProtoICMP, reply.Encode())
}

// isBroadcast reports whether mac is ff:ff:ff:ff:ff:ff, the Ethernet
// "everyone on this link" address. Multicast addresses do not count.
func isBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

// macEqual reports whether a and b are the same hardware address.
func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
