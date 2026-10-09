// Package udp is the User Datagram Protocol (RFC 768): ports, a length,
// and a checksum in front of one message. No connections, no ordering, no
// retransmission; whoever sends a datagram decides what to do when no
// answer comes. mytcp uses it for one thing, DNS.
package udp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

// HeaderLen is the fixed size of a UDP header.
const HeaderLen = 8

// Datagram is one UDP message.
//
//	0      2      4      6      8
//	+------+------+------+------+---------
//	| src  | dst  | len  | sum  | payload
//	+------+------+------+------+---------
type Datagram struct {
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// Decode reads a datagram from an IPv4 payload. The length field must fit
// inside b; bytes beyond it (Ethernet padding) are dropped. The checksum
// is not verified, as with TCP and IPv4.
func Decode(b []byte) (Datagram, error) {
	if len(b) < HeaderLen {
		return Datagram{}, fmt.Errorf("udp: datagram too short (%d)", len(b))
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n < HeaderLen || n > len(b) {
		return Datagram{}, fmt.Errorf("udp: bad length %d for %d bytes", n, len(b))
	}
	return Datagram{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Payload: append([]byte(nil), b[HeaderLen:n]...),
	}, nil
}

// Encode builds the wire bytes. src and dst are the IPv4 addresses the
// datagram will travel between: like TCP, UDP checksums a pseudo-header
// taken from the IP layer.
func (d Datagram) Encode(src, dst net.IP) []byte {
	out := make([]byte, HeaderLen+len(d.Payload))
	binary.BigEndian.PutUint16(out[0:2], d.SrcPort)
	binary.BigEndian.PutUint16(out[2:4], d.DstPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)))
	copy(out[HeaderLen:], d.Payload)

	pseudo := make([]byte, 12+len(out))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = ip4.ProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(out)))
	copy(pseudo[12:], out)
	sum := ip4.Checksum(pseudo)
	// In UDP a checksum of 0 means "none was computed", so a real sum of
	// 0 is sent as its ones'-complement twin, 0xffff.
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(out[6:8], sum)
	return out
}
