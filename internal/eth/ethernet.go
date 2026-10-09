// Package eth is the link layer: Ethernet II framing (RFC 894 describes
// carrying IP inside these frames).
//
// Below it is the TAP device, which hands us raw frames as byte slices.
// Above it are ARP and IPv4: this package peels off the 14-byte header,
// reports which protocol the payload belongs to (the EtherType), and
// hands the payload up. On the way down it does the reverse.
//
// Deliberately left out: the 4-byte frame check sequence (the TAP driver
// never shows it to us), 802.1Q VLAN tags, 802.3 length-style frames, and
// padding short frames to the 60-byte Ethernet minimum.
package eth

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// HeaderLen is the size of an Ethernet II header:
	// 6 bytes destination MAC + 6 bytes source MAC + 2 bytes EtherType.
	HeaderLen = 14
	// TypeARP is the EtherType value that means "the payload is an ARP message".
	TypeARP = 0x0806
	// TypeIPv4 is the EtherType value that means "the payload is an IPv4 packet".
	TypeIPv4 = 0x0800
)

// Frame is one Ethernet II frame, without the trailing FCS checksum
// (the TAP driver strips it on receive and the kernel adds it on send).
type Frame struct {
	Dst     net.HardwareAddr // who the frame is for; ff:ff:ff:ff:ff:ff is broadcast
	Src     net.HardwareAddr // who sent it
	Type    uint16           // EtherType: which protocol is in Payload
	Payload []byte           // everything after the 14-byte header
}

// Decode decodes an Ethernet II frame. The on-the-wire layout is:
//
//	0        6        12     14
//	+--------+--------+------+-------------
//	|  dst   |  src   | type | payload...
//	|  MAC   |  MAC   |      | (ARP, IPv4, ...)
//	+--------+--------+------+-------------
//
// The EtherType is big-endian (network byte order), like every multi-byte
// field in these protocols. MAC addresses and payload are copied, so the
// returned Frame stays valid after the caller reuses its read buffer.
func Decode(b []byte) (Frame, error) {
	// Anything shorter than the header cannot even say who it is for.
	if len(b) < HeaderLen {
		return Frame{}, fmt.Errorf("ethernet: frame too short (%d)", len(b))
	}
	return Frame{
		Dst:     append(net.HardwareAddr(nil), b[0:6]...),  // bytes 0-5: destination MAC
		Src:     append(net.HardwareAddr(nil), b[6:12]...), // bytes 6-11: source MAC
		Type:    binary.BigEndian.Uint16(b[12:14]),         // bytes 12-13: EtherType, 0x0806 = ARP, 0x0800 = IPv4
		Payload: append([]byte(nil), b[14:]...),            // bytes 14+: the next layer's packet
	}, nil
}

// Encode encodes the frame into wire bytes, using the same layout as Decode.
// It does not pad to the 60-byte Ethernet minimum; the TAP device accepts
// short frames as they are.
func (f Frame) Encode() []byte {
	out := make([]byte, HeaderLen+len(f.Payload))
	copy(out[0:6], f.Dst)                          // bytes 0-5: destination MAC
	copy(out[6:12], f.Src)                         // bytes 6-11: source MAC
	binary.BigEndian.PutUint16(out[12:14], f.Type) // bytes 12-13: EtherType
	copy(out[14:], f.Payload)                      // bytes 14+: payload
	return out
}

// TypeName returns a human-readable name for an EtherType, for logs.
// Unknown types are shown in hex, the way Wireshark shows them.
func TypeName(t uint16) string {
	switch t {
	case TypeARP:
		return "ARP"
	case TypeIPv4:
		return "IPv4"
	default:
		return fmt.Sprintf("0x%04x", t)
	}
}
