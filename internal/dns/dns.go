// Package dns builds DNS queries and reads the answers (RFC 1035), just
// enough to turn a host name into IPv4 addresses: one question, type A,
// class IN, sent over UDP to a recursive resolver that does the real work.
//
// Every message has the same shape:
//
//	+---------------------+
//	| header (12 bytes)   |  ID, flags, and four section counts
//	+---------------------+
//	| question            |  name, type, class
//	+---------------------+
//	| answer records      |  name, type, class, TTL, length, data
//	+---------------------+
//	| authority, extra    |  ignored here
//	+---------------------+
//
// It leaves out AAAA, caching, EDNS, DNSSEC, and the TCP fallback for
// truncated answers.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Record types and the one class we use.
const (
	TypeA     = 1
	TypeCNAME = 5
	ClassIN   = 1
)

// Header flag bits (bytes 2-3).
const (
	flagQR = 1 << 15 // this is a response
	flagTC = 1 << 9  // truncated: the full answer did not fit in UDP
	flagRD = 1 << 8  // recursion desired: please resolve it for me
)

// Response codes (low 4 bits of the flags).
const (
	RcodeOK       = 0
	RcodeServFail = 2
	RcodeNXDomain = 3
)

const headerLen = 12

// maxPointers bounds how many compression pointers one name may follow,
// so a malicious loop cannot spin forever.
const maxPointers = 16

// Query builds a question asking for name's A records.
//
//	header:   ID | flags=RD | QDCOUNT=1 | 0 | 0 | 0
//	question: 7 example 3 com 0 | QTYPE=A | QCLASS=IN
func Query(id uint16, name string) ([]byte, error) {
	qname, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	b := make([]byte, headerLen, headerLen+len(qname)+4)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], flagRD)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, qname...)
	b = binary.BigEndian.AppendUint16(b, TypeA)
	b = binary.BigEndian.AppendUint16(b, ClassIN)
	return b, nil
}

// encodeName writes a name as length-prefixed labels ending in a zero
// byte: "example.com" becomes 7 "example" 3 "com" 0.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, errors.New("dns: empty name")
	}
	var b []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("dns: bad label %q in %q", label, name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	if len(b) > 255 {
		return nil, fmt.Errorf("dns: name too long (%d bytes)", len(b))
	}
	return b, nil
}

// ErrNotFound is returned for NXDOMAIN, and for an answer with no A
// records in it.
var ErrNotFound = errors.New("dns: no such host")

// ParseResponse checks that b answers query id and returns the IPv4
// addresses in its answer section. CNAME records are skipped: a recursive
// resolver puts the whole chain in the answers, A records included.
func ParseResponse(b []byte, id uint16) ([]net.IP, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("dns: message too short (%d)", len(b))
	}
	if got := binary.BigEndian.Uint16(b[0:2]); got != id {
		return nil, fmt.Errorf("dns: reply id %d, want %d", got, id)
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	switch {
	case flags&flagQR == 0:
		return nil, errors.New("dns: not a response")
	case flags&flagTC != 0:
		return nil, errors.New("dns: truncated answer (no TCP fallback)")
	}
	switch rc := flags & 0xf; rc {
	case RcodeOK:
	case RcodeNXDomain:
		return nil, ErrNotFound
	case RcodeServFail:
		return nil, errors.New("dns: server failure")
	default:
		return nil, fmt.Errorf("dns: error code %d", rc)
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))

	off := headerLen
	for range qd {
		n, err := skipName(b, off)
		if err != nil {
			return nil, err
		}
		off = n + 4 // QTYPE, QCLASS
		if off > len(b) {
			return nil, errors.New("dns: question runs past the end")
		}
	}

	var ips []net.IP
	for range an {
		n, err := skipName(b, off)
		if err != nil {
			return nil, err
		}
		// TYPE, CLASS, TTL, RDLENGTH, then RDLENGTH bytes of data.
		if n+10 > len(b) {
			return nil, errors.New("dns: record runs past the end")
		}
		typ := binary.BigEndian.Uint16(b[n : n+2])
		class := binary.BigEndian.Uint16(b[n+2 : n+4])
		rdlen := int(binary.BigEndian.Uint16(b[n+8 : n+10]))
		data := n + 10
		if data+rdlen > len(b) {
			return nil, errors.New("dns: record data runs past the end")
		}
		if typ == TypeA && class == ClassIN && rdlen == 4 {
			ips = append(ips, net.IPv4(b[data], b[data+1], b[data+2], b[data+3]).To4())
		}
		off = data + rdlen
	}
	if len(ips) == 0 {
		return nil, ErrNotFound
	}
	return ips, nil
}

// skipName returns the offset just past the name starting at off. A name
// is labels ending in a zero byte, or ending in a two-byte pointer (top
// bits 11) to a name earlier in the message: that is compression, and
// how "www.google.com" is written once and reused by every record.
func skipName(b []byte, off int) (int, error) {
	end := -1 // where the name ends in the record, set at the first pointer
	for hops := 0; ; {
		if off >= len(b) {
			return 0, errors.New("dns: name runs past the end")
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return end, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return 0, errors.New("dns: pointer runs past the end")
			}
			if hops++; hops > maxPointers {
				return 0, errors.New("dns: compression pointer loop")
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
		case l > 63:
			return 0, fmt.Errorf("dns: bad label length %#x", l)
		default:
			off += 1 + l
		}
	}
}

// readName decodes the name at off, following compression pointers.
func readName(b []byte, off int) (string, error) {
	var labels []string
	for hops := 0; ; {
		if off >= len(b) {
			return "", errors.New("dns: name runs past the end")
		}
		l := int(b[off])
		switch {
		case l == 0:
			return strings.Join(labels, "."), nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", errors.New("dns: pointer runs past the end")
			}
			if hops++; hops > maxPointers {
				return "", errors.New("dns: compression pointer loop")
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
		case l > 63 || off+1+l > len(b):
			return "", fmt.Errorf("dns: bad label at %d", off)
		default:
			labels = append(labels, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

// Describe summarizes a message in one line for packet dumps, such as
// "query id=7 example.com" or "answer id=7 example.com → 2 records".
func Describe(b []byte) string {
	if len(b) < headerLen {
		return "short message"
	}
	id := binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	name := "?"
	if binary.BigEndian.Uint16(b[4:6]) > 0 {
		if n, err := readName(b, headerLen); err == nil {
			name = n
		}
	}
	if flags&flagQR == 0 {
		return fmt.Sprintf("query id=%d %s", id, name)
	}
	if ips, err := ParseResponse(b, id); err == nil {
		return fmt.Sprintf("answer id=%d %s → %s (%d A)", id, name, ips[0], len(ips))
	}
	return fmt.Sprintf("answer id=%d %s rcode=%d", id, name, flags&0xf)
}
