// Package dump prints frames as an unwrapped layer onion for debugging.
//
// Every frame is a set of nested envelopes: an Ethernet header around an
// IPv4 (or ARP) packet, around a TCP (or ICMP) segment, around application
// bytes. Frame peels them off one at a time with the same parsers the stack
// uses and prints one indented line plus a hex dump per layer, so you can
// see exactly which bytes belong to which header.
//
// It only reads; it never changes or answers anything. It decodes the same
// protocols the stack does, plus a best-effort look at HTTP text and DNS
// on port 53. IPv6 is named but not decoded, and TLS payload is shown as
// raw bytes.
package dump

import (
	"fmt"
	"io"
	"strings"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/dns"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
	"github.com/doodlesbykumbi/mytcp/internal/hexdump"
	"github.com/doodlesbykumbi/mytcp/internal/icmp"
	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/tcp"
	"github.com/doodlesbykumbi/mytcp/internal/udp"
)

// Frame writes a full-frame hex dump, then a layered onion decode, to w.
// dir is typically "<<< RX" or ">>> TX".
//
// Each layer prints only its own header bytes, then hands its payload to
// the next layer's dumper. The branching follows the same header fields
// the stack uses: EtherType picks ARP or IPv4, and the IPv4 Protocol
// field picks ICMP or TCP. A decode error stops peeling at that layer
// and prints the undecoded bytes instead.
func Frame(w io.Writer, dir string, b []byte) {
	fmt.Fprintf(w, "%s %d bytes\n", dir, len(b))
	if len(b) == 0 {
		return
	}

	fmt.Fprintf(w, "  full frame\n")
	hexdump.Dump(w, "  ", b)
	fmt.Fprintf(w, "  layers\n")

	f, err := eth.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L2 Ethernet  <decode error: %v>\n", err)
		fmt.Fprintln(w)
		return
	}

	// The Ethernet header is always the first 14 bytes: two MACs and
	// the EtherType.
	fmt.Fprintf(w, "  L2 Ethernet  dst=%s src=%s type=%s\n", f.Dst, f.Src, eth.TypeName(f.Type))
	hexdump.Dump(w, "             ", b[:eth.HeaderLen])

	switch f.Type {
	case eth.TypeARP:
		dumpARP(w, f.Payload)
	case eth.TypeIPv4:
		dumpIPv4(w, f.Payload)
	case 0x86dd:
		// EtherType 0x86DD is IPv6. The host kernel often sends IPv6
		// neighbor discovery on the TAP; the stack drops it.
		fmt.Fprintf(w, "  L3 IPv6     (ignored by stack)\n")
		hexdump.Dump(w, "             ", f.Payload)
	default:
		fmt.Fprintf(w, "  L3 ?        payload %d bytes\n", len(f.Payload))
		hexdump.Dump(w, "             ", f.Payload)
	}
	fmt.Fprintln(w)
}

// dumpARP prints an ARP packet as a sentence: a request reads "who has
// TPA, tell SPA", and a reply reads "SPA is at SHA".
func dumpARP(w io.Writer, b []byte) {
	p, err := arp.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L3 ARP      <decode error: %v>\n", err)
		hexdump.Dump(w, "             ", b)
		return
	}
	op := "?"
	switch p.Op {
	case arp.OpRequest:
		op = "request who-has"
	case arp.OpReply:
		op = "reply is-at"
	}
	// Printed as sender (IP and MAC) → target (IP and MAC). In a request
	// the target MAC is unknown, which is the whole point of asking.
	fmt.Fprintf(w, "  L3 ARP      %s  %s (%s) → %s (%s)\n",
		op, p.SPA, p.SHA, p.TPA, p.THA)
	hexdump.Dump(w, "             ", b)
}

// dumpIPv4 prints the IPv4 header fields that matter for the demo, the
// header bytes on their own, then dispatches on the Protocol field.
func dumpIPv4(w io.Writer, b []byte) {
	pkt, err := ip4.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L3 IPv4     <decode error: %v>\n", err)
		hexdump.Dump(w, "             ", b)
		return
	}
	// The header length is not fixed: the low 4 bits of the first byte
	// (IHL) give it in 32-bit words, so 5 means 20 bytes and more means
	// options are present. ip4.Packet does not keep it, so recompute it
	// here to know how many bytes to show as "header". Fall back to 20
	// (clamped to the data we have) if the field looks wrong.
	ihl := 20
	if len(b) >= 1 {
		ihl = int(b[0]&0x0f) * 4
		if ihl < 20 || ihl > len(b) {
			ihl = 20
			if ihl > len(b) {
				ihl = len(b)
			}
		}
	}
	fmt.Fprintf(w, "  L3 IPv4     %s → %s  proto=%s ttl=%d id=0x%04x payload=%dB\n",
		pkt.Src, pkt.Dst, ip4.ProtoName(pkt.Proto), pkt.TTL, pkt.ID, len(pkt.Payload))
	hexdump.Dump(w, "             ", b[:ihl])

	switch pkt.Proto {
	case ip4.ProtoICMP:
		dumpICMP(w, pkt.Payload)
	case ip4.ProtoTCP:
		dumpTCP(w, pkt.Payload)
	case ip4.ProtoUDP:
		dumpUDP(w, pkt.Payload)
	default:
		fmt.Fprintf(w, "  L4 ?        proto=%s %d bytes\n", ip4.ProtoName(pkt.Proto), len(pkt.Payload))
		hexdump.Dump(w, "             ", pkt.Payload)
	}
}

// dumpICMP prints an ICMP message using the echo layout: type, code,
// identifier, sequence number, then the payload. For message types other
// than echo request and reply, the id and seq fields are just whatever
// bytes sit at those offsets.
func dumpICMP(w io.Writer, b []byte) {
	echo, err := icmp.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L4 ICMP     <decode error: %v>\n", err)
		hexdump.Dump(w, "             ", b)
		return
	}
	kind := fmt.Sprintf("type=%d code=%d", echo.Type, echo.Code)
	switch echo.Type {
	case icmp.TypeEcho:
		kind = "echo-request"
	case icmp.TypeEchoReply:
		kind = "echo-reply"
	}
	fmt.Fprintf(w, "  L4 ICMP     %s id=%d seq=%d payload=%dB\n",
		kind, echo.ID, echo.Seq, len(echo.Payload))
	hdrEnd := icmp.HeaderLen
	if hdrEnd > len(b) {
		hdrEnd = len(b)
	}
	hexdump.Dump(w, "             ", b[:hdrEnd])
	// Linux ping fills the payload with a timestamp and a byte pattern;
	// a reply must echo it back unchanged.
	if len(echo.Payload) > 0 {
		fmt.Fprintf(w, "  payload     %q\n", truncate(echo.Payload, 48))
		hexdump.Dump(w, "             ", echo.Payload)
	}
}

// dumpTCP prints a TCP segment's ports, flags, sequence and ack numbers,
// window, and header length, then its payload. Payload that starts like
// HTTP gets one more layer of decoding.
func dumpTCP(w io.Writer, b []byte) {
	seg, err := tcp.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L4 TCP      <decode error: %v>\n", err)
		hexdump.Dump(w, "             ", b)
		return
	}
	fmt.Fprintf(w, "  L4 TCP      %d → %d  %s seq=%d ack=%d win=%d hdr=%d payload=%dB\n",
		seg.SrcPort, seg.DstPort, tcp.FlagsString(seg.Flags),
		seg.Seq, seg.Ack, seg.Window, seg.HdrLen, len(seg.Payload))
	// HdrLen comes from the data offset field and includes any TCP
	// options (such as MSS in a SYN), which is why it can exceed 20.
	hdrEnd := seg.HdrLen
	if hdrEnd > len(b) {
		hdrEnd = len(b)
	}
	hexdump.Dump(w, "             ", b[:hdrEnd])
	// Pure ACKs, and SYN or FIN segments, usually carry no data.
	if len(seg.Payload) == 0 {
		return
	}
	if looksLikeHTTP(seg.Payload) {
		dumpHTTP(w, seg.Payload)
		return
	}
	fmt.Fprintf(w, "  payload     %q\n", truncate(seg.Payload, 48))
	hexdump.Dump(w, "             ", seg.Payload)
}

// dumpUDP prints a UDP datagram's ports and length, then its payload.
// Either port being 53 means DNS, which gets one more layer.
func dumpUDP(w io.Writer, b []byte) {
	d, err := udp.Decode(b)
	if err != nil {
		fmt.Fprintf(w, "  L4 UDP      <decode error: %v>\n", err)
		hexdump.Dump(w, "             ", b)
		return
	}
	fmt.Fprintf(w, "  L4 UDP      %d → %d  payload=%dB\n", d.SrcPort, d.DstPort, len(d.Payload))
	hexdump.Dump(w, "             ", b[:udp.HeaderLen])
	if len(d.Payload) == 0 {
		return
	}
	if d.SrcPort == 53 || d.DstPort == 53 {
		fmt.Fprintf(w, "  L7 DNS      %s\n", dns.Describe(d.Payload))
	} else {
		fmt.Fprintf(w, "  payload     %q\n", truncate(d.Payload, 48))
	}
	hexdump.Dump(w, "             ", d.Payload)
}

// looksLikeHTTP guesses whether a TCP payload is the start of an HTTP/1
// message, by checking for a response status line ("HTTP/") or a common
// request method followed by a space. It is a heuristic: TCP has no idea
// what it carries, and a segment in the middle of a message will not match.
func looksLikeHTTP(b []byte) bool {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "HTTP/"):
		return true
	case strings.HasPrefix(s, "GET "),
		strings.HasPrefix(s, "HEAD "),
		strings.HasPrefix(s, "POST "),
		strings.HasPrefix(s, "PUT "),
		strings.HasPrefix(s, "DELETE "),
		strings.HasPrefix(s, "OPTIONS "),
		strings.HasPrefix(s, "PATCH "):
		return true
	default:
		return false
	}
}

// dumpHTTP prints an HTTP/1 message as the L7 layer: the start line, one
// header field per line, then the body. HTTP/1 is plain text, so unlike
// the layers below, the "decode" is mostly splitting on \r\n.
func dumpHTTP(w io.Writer, b []byte) {
	head, body, ok := splitHTTP(b)
	if !ok {
		// Looks like HTTP start but no header terminator yet (or truncated).
		line, _, _ := strings.Cut(string(b), "\r\n")
		fmt.Fprintf(w, "  L7 HTTP     (incomplete) %q\n", truncate([]byte(line), 72))
		hexdump.Dump(w, "             ", b)
		return
	}

	lines := strings.Split(head, "\r\n")
	start := ""
	if len(lines) > 0 {
		start = lines[0]
	}
	fmt.Fprintf(w, "  L7 HTTP     %s\n", start)
	for _, h := range lines[1:] {
		if h == "" {
			continue
		}
		fmt.Fprintf(w, "             %s\n", h)
	}
	// Show the header bytes including the blank line that ends them, so
	// the 0d 0a 0d 0a terminator is visible in the hex.
	hexdump.Dump(w, "             ", []byte(head+"\r\n\r\n"))
	if len(body) > 0 {
		fmt.Fprintf(w, "  body        %q\n", truncate(body, 64))
		hexdump.Dump(w, "             ", body)
	}
}

// splitHTTP splits b at the first blank line (\r\n\r\n) into the header
// section and whatever follows it. ok is false if the blank line has not
// arrived in this segment.
func splitHTTP(b []byte) (head string, body []byte, ok bool) {
	const sep = "\r\n\r\n"
	i := strings.Index(string(b), sep)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), append([]byte(nil), b[i+len(sep):]...), true
}

// truncate returns b as a string, cut to n bytes with an ellipsis if it is
// longer. It cuts on a byte boundary, so it can split a multi-byte UTF-8
// character; that is fine for a debug dump.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
