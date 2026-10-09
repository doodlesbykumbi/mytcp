// Package ip4 is the network layer: IPv4 (RFC 791).
//
// Below it is Ethernet, which hands up frame payloads with EtherType 0x0800.
// This package decodes the IPv4 header, and hands the payload up to ICMP or
// TCP based on the protocol number. On the way down it wraps their bytes in
// a fresh 20-byte header with a correct checksum. It also provides the
// Internet checksum (RFC 1071) that ICMP and TCP reuse.
//
// Deliberately left out: IP options (skipped on decode, never sent),
// fragmentation and reassembly, header checksum verification on receive,
// and routing (there is only one link, the TAP device).
package ip4

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// MinHeaderLen is the size of an IPv4 header with no options.
	// Options can grow it up to 60 bytes, but this stack never sends any.
	MinHeaderLen = 20
	// ProtoICMP is the IPv4 protocol number for ICMP.
	ProtoICMP = 1
	// ProtoTCP is the IPv4 protocol number for TCP.
	ProtoTCP = 6
	// ProtoUDP is the IPv4 protocol number for UDP.
	ProtoUDP = 17
)

// Packet is an IPv4 datagram (options ignored / stripped on decode).
// Fields that the stack computes itself (version, header length, total
// length, checksum) are not stored; Encode fills them in.
type Packet struct {
	TOS       uint8  // type of service / DSCP; 0 means ordinary traffic
	ID        uint16 // identification, used to reassemble fragments
	FlagsFrag uint16 // top 3 bits: flags (e.g. Don't Fragment), low 13 bits: fragment offset
	TTL       uint8  // time to live: hop limit, decremented by every router
	Proto     uint8  // which protocol is in Payload: ProtoICMP, ProtoTCP, ...
	Src       net.IP // source address
	Dst       net.IP // destination address
	Payload   []byte // the ICMP or TCP message
}

// Decode decodes an IPv4 packet. The on-the-wire header layout is:
//
//	0       1       2       4       6       8     9     10       12      16      20
//	+-------+-------+-------+-------+-------+-----+-----+--------+-------+-------+----------
//	|ver|ihl|  TOS  | total |  ID   | flags | TTL |proto|checksum|  src  |  dst  | options /
//	|       |       |length |       | +frag |     |     |        |  IP   |  IP   | payload...
//	+-------+-------+-------+-------+-------+-----+-----+--------+-------+-------+----------
//
// Multi-byte fields are big-endian (network byte order). Options, if the
// header has any, are skipped. The checksum is not verified. Fragments are
// not detected: a fragment is returned as if it were a whole packet.
func Decode(b []byte) (Packet, error) {
	if len(b) < MinHeaderLen {
		return Packet{}, fmt.Errorf("ipv4: too short (%d)", len(b))
	}
	// Byte 0 packs two 4-bit fields: the version (high nibble, must be 4)
	// and the IHL (low nibble), the header length in 32-bit words.
	vihl := b[0]
	if vihl>>4 != 4 {
		return Packet{}, fmt.Errorf("ipv4: not v4 (version=%d)", vihl>>4)
	}
	// IHL counts 4-byte words, so 5 means 20 bytes (no options) and the
	// maximum, 15, means 60 bytes. Anything past byte 20 is options.
	ihl := int(vihl&0x0f) * 4
	if ihl < MinHeaderLen || len(b) < ihl {
		return Packet{}, fmt.Errorf("ipv4: bad IHL (%d)", ihl)
	}
	// Bytes 2-3: total length of header plus payload. It can be smaller than
	// len(b), because Ethernet pads short frames up to its 60-byte minimum;
	// slicing to total below drops that padding.
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		// A total shorter than the header is nonsense, so reject it. A total
		// longer than the bytes actually received means the packet was cut
		// short; it is accepted, and the payload is whatever arrived.
		if total < ihl {
			return Packet{}, fmt.Errorf("ipv4: bad total length (%d)", total)
		}
		total = len(b)
	}
	return Packet{
		TOS:       b[1],                                     // byte 1: type of service
		ID:        binary.BigEndian.Uint16(b[4:6]),          // bytes 4-5: identification
		FlagsFrag: binary.BigEndian.Uint16(b[6:8]),          // bytes 6-7: flags + fragment offset
		TTL:       b[8],                                     // byte 8: time to live
		Proto:     b[9],                                     // byte 9: protocol, 1 = ICMP, 6 = TCP
		Src:       net.IP(append([]byte(nil), b[12:16]...)), // bytes 12-15: source IP (bytes 10-11, the checksum, are skipped)
		Dst:       net.IP(append([]byte(nil), b[16:20]...)), // bytes 16-19: destination IP
		Payload:   append([]byte(nil), b[ihl:total]...),     // after the header (and any options), up to total length
	}, nil
}

// Encode encodes the packet into wire bytes, using the same layout as
// Decode. It always writes a 20-byte header with no options, computes the
// total length and the header checksum, and uses a TTL of 64 when p.TTL
// is zero. It does not fragment: the caller must keep the payload small
// enough for the link.
func (p Packet) Encode() []byte {
	payload := p.Payload
	total := MinHeaderLen + len(payload)
	out := make([]byte, total)
	out[0] = 0x45                                       // byte 0: version 4, IHL 5 (5 x 4 = 20 bytes, no options)
	out[1] = p.TOS                                      // byte 1: type of service
	binary.BigEndian.PutUint16(out[2:4], uint16(total)) // bytes 2-3: total length, header + payload
	binary.BigEndian.PutUint16(out[4:6], p.ID)          // bytes 4-5: identification
	binary.BigEndian.PutUint16(out[6:8], p.FlagsFrag)   // bytes 6-7: flags + fragment offset
	// Byte 8: TTL. Zero would be dropped by the first router, so treat it
	// as "not set" and use 64, a common default (Linux uses it too).
	if p.TTL == 0 {
		out[8] = 64
	} else {
		out[8] = p.TTL
	}
	out[9] = p.Proto              // byte 9: protocol of the payload
	copy(out[12:16], p.Src.To4()) // bytes 12-15: source IP
	copy(out[16:20], p.Dst.To4()) // bytes 16-19: destination IP
	// Bytes 10-11: header checksum. It covers only the 20 header bytes, not
	// the payload, and is computed while those two bytes are still zero.
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:MinHeaderLen]))
	copy(out[MinHeaderLen:], payload)
	return out
}

// Checksum computes the Internet checksum over b (checksum field should be 0).
//
// This is the RFC 1071 algorithm shared by IPv4, ICMP and TCP: treat the
// data as a sequence of big-endian 16-bit words, add them up using
// ones'-complement arithmetic, and return the bitwise NOT of the sum.
// Ones'-complement addition means a carry out of the top bit wraps around
// and is added back in at the bottom. A receiver that sums the data
// including the stored checksum gets 0xffff when nothing is corrupted.
func Checksum(b []byte) uint16 {
	// Accumulate in 32 bits so carries out of the 16-bit words are kept
	// in the upper half instead of being lost.
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	// An odd trailing byte is treated as the high byte of a word whose low
	// byte is zero, as if the data were padded with one zero byte.
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	// Fold the carries back in: add the upper 16 bits to the lower 16 bits
	// until the sum fits in 16 bits. This is the ones'-complement wraparound.
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ProtoName returns a human-readable name for an IPv4 protocol number,
// for logs. Unknown numbers are shown in decimal.
func ProtoName(p uint8) string {
	switch p {
	case ProtoICMP:
		return "ICMP"
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	default:
		return fmt.Sprintf("%d", p)
	}
}
