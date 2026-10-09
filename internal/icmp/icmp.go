// Package icmp implements the ICMP echo messages (RFC 792) behind ping.
//
// ICMP rides inside IPv4 (protocol number 1). The IPv4 layer hands this
// package the IP payload; this package decodes an echo request and builds
// the matching echo reply, which goes back down to IPv4 to be wrapped.
//
// Deliberately left out: every other ICMP message type (destination
// unreachable, time exceeded, redirects, ...) and checksum verification
// of incoming messages.
package icmp

import (
	"encoding/binary"
	"fmt"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

const (
	// HeaderLen is the size of the ICMP echo header: type, code,
	// checksum, identifier and sequence number.
	HeaderLen = 8
	// TypeEcho is the ICMP type of an echo request (what ping sends).
	TypeEcho = 8
	// TypeEchoReply is the ICMP type of an echo reply (what ping waits for).
	TypeEchoReply = 0
)

// Echo is an ICMP echo request/reply.
type Echo struct {
	Type    uint8  // TypeEcho or TypeEchoReply
	Code    uint8  // always 0 for echo messages
	ID      uint16 // identifier chosen by ping so it can match replies to its own requests
	Seq     uint16 // sequence number, incremented by ping for each request
	Payload []byte // arbitrary data; a reply must echo it back unchanged
}

// Decode decodes an ICMP echo message. The on-the-wire layout is:
//
//	0      1      2          4          6          8
//	+------+------+----------+----------+----------+-------------
//	| type | code | checksum |    id    |   seq    | payload...
//	+------+------+----------+----------+----------+-------------
//
// Multi-byte fields are big-endian (network byte order). The checksum is
// not verified, and the type is not checked: the caller decides whether
// this really is an echo request.
func Decode(b []byte) (Echo, error) {
	if len(b) < HeaderLen {
		return Echo{}, fmt.Errorf("icmp: too short (%d)", len(b))
	}
	return Echo{
		Type:    b[0],                            // byte 0: type, 8 = echo request, 0 = echo reply
		Code:    b[1],                            // byte 1: code, 0 for echo
		ID:      binary.BigEndian.Uint16(b[4:6]), // bytes 4-5: identifier (bytes 2-3, the checksum, are skipped)
		Seq:     binary.BigEndian.Uint16(b[6:8]), // bytes 6-7: sequence number
		Payload: append([]byte(nil), b[8:]...),   // bytes 8+: data to echo back
	}, nil
}

// Encode encodes the message into wire bytes, using the same layout as
// Decode, and fills in the checksum.
func (e Echo) Encode() []byte {
	out := make([]byte, HeaderLen+len(e.Payload))
	out[0] = e.Type                             // byte 0: type
	out[1] = e.Code                             // byte 1: code
	binary.BigEndian.PutUint16(out[4:6], e.ID)  // bytes 4-5: identifier
	binary.BigEndian.PutUint16(out[6:8], e.Seq) // bytes 6-7: sequence number
	copy(out[8:], e.Payload)                    // bytes 8+: payload
	// The ICMP checksum covers the whole message, header and payload, and is
	// the same Internet checksum IPv4 uses. It is computed last, while
	// bytes 2-3 are still zero, and then written into those bytes.
	binary.BigEndian.PutUint16(out[2:4], ip4.Checksum(out))
	return out
}

// ReplyFrom turns an echo request into an echo reply.
// The type becomes echo reply and the code is 0. ID, sequence number and
// payload are copied unchanged, which is how ping matches the reply to its
// request. The checksum is recomputed later, by Encode.
func ReplyFrom(req Echo) Echo {
	return Echo{
		Type:    TypeEchoReply,
		Code:    0,
		ID:      req.ID,
		Seq:     req.Seq,
		Payload: req.Payload,
	}
}
