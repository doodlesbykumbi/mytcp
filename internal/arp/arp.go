// Package arp implements the Address Resolution Protocol (RFC 826) for
// IPv4 over Ethernet.
//
// ARP answers the question "which MAC address owns this IP address?".
// It rides directly inside an Ethernet frame (EtherType 0x0806) and has no
// layer above it. The kernel on the other side of the TAP device asks who
// owns our IP; this package decodes that request and builds the reply. When
// we start a connection ourselves, it builds our own request. The cache of
// learned addresses lives in the stack package.
//
// Deliberately left out: any hardware/protocol pair other than
// Ethernet/IPv4, and gratuitous ARP.
package arp

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// HeaderLen is the size of an Ethernet/IPv4 ARP message. ARP is generic,
	// but with 6-byte MACs and 4-byte IPs it is always exactly 28 bytes:
	// 8 bytes of fixed header plus two (MAC, IP) pairs of 10 bytes each.
	HeaderLen = 28 // Ethernet/IPv4 ARP
	// OpRequest is the operation code for "who has this IP?".
	OpRequest = 1
	// OpReply is the operation code for "this IP is at this MAC".
	OpReply = 2
	// HWEther is the ARP hardware type number for Ethernet.
	HWEther = 1
	// ProtoIPv4 is the protocol type for IPv4. ARP reuses the EtherType
	// numbers here, so it is the same 0x0800 used in the Ethernet header.
	ProtoIPv4 = 0x0800
)

// Packet is an Ethernet/IPv4 ARP message. The names follow RFC 826:
// "S" is sender, "T" is target, "HA" is hardware (MAC) address and
// "PA" is protocol (IP) address.
type Packet struct {
	Op  uint16           // OpRequest or OpReply
	SHA net.HardwareAddr // sender MAC
	SPA net.IP           // sender IP
	THA net.HardwareAddr // target MAC (all zeros in a request: that is what is being asked)
	TPA net.IP           // target IP (in a request: the IP being looked up)
}

// Decode decodes an ARP message. The on-the-wire layout for Ethernet/IPv4 is:
//
//	0      2      4    5    6      8          14       18         24       28
//	+------+------+----+----+------+----------+--------+----------+--------+
//	|  hw  |proto |hlen|plen|  op  |  sender  | sender |  target  | target |
//	| type | type | =6 | =4 |      |   MAC    |   IP   |   MAC    |   IP   |
//	+------+------+----+----+------+----------+--------+----------+--------+
//
// Multi-byte fields are big-endian (network byte order). Addresses are
// copied out of b. Messages for any other hardware/protocol combination
// are rejected.
func Decode(b []byte) (Packet, error) {
	if len(b) < HeaderLen {
		return Packet{}, fmt.Errorf("arp: too short (%d)", len(b))
	}
	hwType := binary.BigEndian.Uint16(b[0:2]) // bytes 0-1: hardware type, 1 = Ethernet
	proto := binary.BigEndian.Uint16(b[2:4])  // bytes 2-3: protocol type, 0x0800 = IPv4
	hwLen, protoLen := b[4], b[5]             // byte 4: MAC length (6), byte 5: IP length (4)
	// The offsets below are only valid for 6-byte MACs and 4-byte IPs,
	// so refuse anything else rather than misread it.
	if hwType != HWEther || proto != ProtoIPv4 || hwLen != 6 || protoLen != 4 {
		return Packet{}, fmt.Errorf("arp: unsupported hw/proto (%d/%d %d/%d)", hwType, proto, hwLen, protoLen)
	}
	return Packet{
		Op:  binary.BigEndian.Uint16(b[6:8]),            // bytes 6-7: operation, 1 = request, 2 = reply
		SHA: append(net.HardwareAddr(nil), b[8:14]...),  // bytes 8-13: sender MAC
		SPA: net.IP(append([]byte(nil), b[14:18]...)),   // bytes 14-17: sender IP
		THA: append(net.HardwareAddr(nil), b[18:24]...), // bytes 18-23: target MAC
		TPA: net.IP(append([]byte(nil), b[24:28]...)),   // bytes 24-27: target IP
	}, nil
}

// Encode encodes the message into its 28 wire bytes, using the same layout
// as Decode. The hardware and protocol fields are always Ethernet/IPv4.
func (p Packet) Encode() []byte {
	out := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(out[0:2], HWEther)   // bytes 0-1: hardware type = Ethernet
	binary.BigEndian.PutUint16(out[2:4], ProtoIPv4) // bytes 2-3: protocol type = IPv4
	out[4], out[5] = 6, 4                           // bytes 4-5: a MAC is 6 bytes, an IPv4 address is 4
	binary.BigEndian.PutUint16(out[6:8], p.Op)      // bytes 6-7: operation
	copy(out[8:14], p.SHA)                          // bytes 8-13: sender MAC
	// net.IP may hold an IPv4 address in 16-byte form; To4 gives the 4 wire bytes.
	copy(out[14:18], p.SPA.To4()) // bytes 14-17: sender IP
	copy(out[18:24], p.THA)       // bytes 18-23: target MAC
	copy(out[24:28], p.TPA.To4()) // bytes 24-27: target IP
	return out
}

// ReplyFor builds an ARP reply claiming ourMAC owns ourIP, answering req.
// The sender and target swap roles: we become the sender, and the original
// asker becomes the target, so the reply goes straight back to them.
// It does not check that req actually asked about ourIP; the caller decides
// whether to answer.
func ReplyFor(req Packet, ourMAC net.HardwareAddr, ourIP net.IP) Packet {
	return Packet{
		Op:  OpReply,
		SHA: ourMAC, // the answer to the question: "ourIP is at ourMAC"
		SPA: ourIP.To4(),
		THA: req.SHA, // send it back to whoever asked
		TPA: req.SPA,
	}
}

// RequestFor builds an ARP request asking who owns target. The target MAC
// is all zeros because that is the unknown; the request is sent to the
// Ethernet broadcast address so every host on the link sees it.
func RequestFor(ourMAC net.HardwareAddr, ourIP, target net.IP) Packet {
	return Packet{
		Op:  OpRequest,
		SHA: ourMAC,
		SPA: ourIP.To4(),
		THA: make(net.HardwareAddr, 6),
		TPA: target.To4(),
	}
}
