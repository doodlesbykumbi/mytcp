package tcp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

// Header size and flag bits.
//
// MinHeaderLen is the size of a TCP header with no options: five 32-bit
// words. The flag constants are the bits of header byte 13. We only use
// the five that matter for a basic connection; URG, ECE and CWR are
// never set and never interpreted.
const (
	MinHeaderLen = 20

	FlagFIN = 0x01 // "I have no more data to send" (consumes one sequence number)
	FlagSYN = 0x02 // "let's synchronize sequence numbers" (consumes one sequence number)
	FlagRST = 0x04 // "abort this connection right now"
	FlagPSH = 0x08 // "hand this to the application without waiting for more"
	FlagACK = 0x10 // the Ack field is valid
)

// Segment is one TCP segment: the header fields we care about plus the
// payload. It is what IPv4 hands us (via Decode) and what we hand back to
// IPv4 (via Encode).
//
// On the wire the header looks like this (RFC 9293 section 3.1).
// All multi-byte fields are big-endian ("network byte order").
//
//	offset  0               1               2               3
//	       +---------------+---------------+---------------+---------------+
//	    0  |          Source Port          |       Destination Port        |
//	       +---------------+---------------+---------------+---------------+
//	    4  |                        Sequence Number                        |
//	       +---------------+---------------+---------------+---------------+
//	    8  |                     Acknowledgment Number                     |
//	       +-------+-------+---------------+---------------+---------------+
//	   12  | DOff  | Rsvd  |     Flags     |            Window             |
//	       +-------+-------+---------------+---------------+---------------+
//	   16  |           Checksum            |        Urgent Pointer         |
//	       +---------------+---------------+---------------+---------------+
//	   20  |                  Options (0-40 bytes, optional)               |
//	       +---------------------------------------------------------------+
//	       |                         Payload ...                           |
//
// DOff ("data offset") is the header length in 32-bit words, so the
// payload starts at DOff*4. Seq is the stream position of the first
// payload byte; Ack is the next byte the sender expects from us.
// Window is how many more bytes the sender is willing to receive.
//
// Options (MSS, window scale, SACK, timestamps) are skipped over on input
// using DOff and never generated on output. The urgent pointer is ignored.
type Segment struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	Payload []byte
	HdrLen  int // header length in bytes including options, as received
}

// Decode decodes a TCP segment from an IPv4 payload. It validates only the
// length and data offset. It does not verify the checksum.
func Decode(b []byte) (Segment, error) {
	if len(b) < MinHeaderLen {
		return Segment{}, fmt.Errorf("tcp: too short (%d)", len(b))
	}
	// The high nibble of byte 12 is the header length in 4-byte words.
	// Anything past 20 bytes is options, which we skip.
	dataOff := int(b[12]>>4) * 4
	if dataOff < MinHeaderLen || dataOff > len(b) {
		return Segment{}, fmt.Errorf("tcp: bad data offset (%d)", dataOff)
	}
	return Segment{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Seq:     binary.BigEndian.Uint32(b[4:8]),
		Ack:     binary.BigEndian.Uint32(b[8:12]),
		Flags:   b[13],
		Window:  binary.BigEndian.Uint16(b[14:16]),
		HdrLen:  dataOff,
		// Copy the payload so the segment does not alias the caller's
		// receive buffer, which gets reused for the next frame.
		Payload: append([]byte(nil), b[dataOff:]...),
	}, nil
}

// Encode encodes the segment into wire bytes, ready to become an IPv4
// payload. The source and destination IPs are needed because the TCP
// checksum covers a pseudo-header built from them (see pseudoChecksum).
// The output always has a 20-byte header with no options and a zero
// urgent pointer.
func (s Segment) Encode(srcIP, dstIP net.IP) []byte {
	hdrLen := MinHeaderLen
	out := make([]byte, hdrLen+len(s.Payload))
	binary.BigEndian.PutUint16(out[0:2], s.SrcPort)
	binary.BigEndian.PutUint16(out[2:4], s.DstPort)
	binary.BigEndian.PutUint32(out[4:8], s.Seq)
	binary.BigEndian.PutUint32(out[8:12], s.Ack)
	// Data offset goes in the high nibble: 20 bytes / 4 = 5 words, so 0x50.
	out[12] = byte((hdrLen / 4) << 4)
	out[13] = s.Flags
	binary.BigEndian.PutUint16(out[14:16], s.Window)
	copy(out[hdrLen:], s.Payload)
	// The checksum is computed with the checksum field still zero, then
	// written into bytes 16-17.
	sum := pseudoChecksum(srcIP, dstIP, out)
	binary.BigEndian.PutUint16(out[16:18], sum)
	return out
}

// pseudoChecksum computes the TCP checksum for tcpSeg.
//
// TCP does not checksum just its own bytes. It prepends a 12-byte
// "pseudo-header" taken from the IP layer, so that a segment delivered to
// the wrong host or the wrong protocol fails the check:
//
//	+--------+--------+--------+--------+
//	|          Source IP address        |
//	+--------+--------+--------+--------+
//	|       Destination IP address      |
//	+--------+--------+--------+--------+
//	|  zero  | proto=6|    TCP length   |
//	+--------+--------+--------+--------+
//
// The pseudo-header is never sent. Both ends rebuild it and include it in
// the same 16-bit ones' complement sum that IPv4 uses for its header.
func pseudoChecksum(src, dst net.IP, tcpSeg []byte) uint16 {
	src4, dst4 := src.To4(), dst.To4()
	pseudo := make([]byte, 12+len(tcpSeg))
	copy(pseudo[0:4], src4)
	copy(pseudo[4:8], dst4)
	// pseudo[8] stays zero (the reserved byte).
	pseudo[9] = ip4.ProtoTCP
	// TCP length is header plus payload, not including the pseudo-header.
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSeg)))
	copy(pseudo[12:], tcpSeg)
	// The checksum field is already zero in tcpSeg, as the algorithm requires.
	return ip4.Checksum(pseudo)
}

// Has reports whether the given flag bit is set on the segment.
func (s Segment) Has(flag uint8) bool { return s.Flags&flag != 0 }

// FlagsString renders flag bits as a comma-separated list such as
// "SYN,ACK", or "-" when no flags are set. It is used for logging.
func FlagsString(f uint8) string {
	var b []byte
	if f&FlagFIN != 0 {
		b = append(b, "FIN"...)
		b = append(b, ',')
	}
	if f&FlagSYN != 0 {
		b = append(b, "SYN"...)
		b = append(b, ',')
	}
	if f&FlagRST != 0 {
		b = append(b, "RST"...)
		b = append(b, ',')
	}
	if f&FlagPSH != 0 {
		b = append(b, "PSH"...)
		b = append(b, ',')
	}
	if f&FlagACK != 0 {
		b = append(b, "ACK"...)
		b = append(b, ',')
	}
	if len(b) == 0 {
		return "-"
	}
	// Drop the trailing comma.
	return string(b[:len(b)-1])
}
