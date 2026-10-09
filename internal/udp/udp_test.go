package udp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

var (
	src = net.IPv4(10, 0, 0, 2)
	dst = net.IPv4(1, 1, 1, 1)
)

func TestRoundTrip(t *testing.T) {
	d := Datagram{SrcPort: 49152, DstPort: 53, Payload: []byte("query")}
	b := d.Encode(src, dst)
	if len(b) != HeaderLen+5 || binary.BigEndian.Uint16(b[4:6]) != 13 {
		t.Fatalf("length: %d bytes, field %d", len(b), binary.BigEndian.Uint16(b[4:6]))
	}
	got, err := Decode(append(b, 0, 0)) // trailing padding is ignored
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcPort != 49152 || got.DstPort != 53 || !bytes.Equal(got.Payload, d.Payload) {
		t.Fatalf("got %+v", got)
	}
}

// Summing the pseudo-header and the datagram, stored checksum included,
// must give 0 after the final complement, just as the receiver checks it.
func TestChecksumVerifies(t *testing.T) {
	b := Datagram{SrcPort: 1234, DstPort: 53, Payload: []byte("abc")}.Encode(src, dst)
	pseudo := make([]byte, 12, 12+len(b))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = ip4.ProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(b)))
	if got := ip4.Checksum(append(pseudo, b...)); got != 0 {
		t.Fatalf("checksum residue %#04x, want 0", got)
	}
	if binary.BigEndian.Uint16(b[6:8]) == 0 {
		t.Fatal("checksum field is 0, which means none")
	}
}

func TestDecodeRejects(t *testing.T) {
	if _, err := Decode([]byte{0, 1, 0, 2}); err == nil {
		t.Fatal("short datagram accepted")
	}
	b := Datagram{SrcPort: 1, DstPort: 2, Payload: []byte("x")}.Encode(src, dst)
	binary.BigEndian.PutUint16(b[4:6], 100)
	if _, err := Decode(b); err == nil {
		t.Fatal("length beyond the buffer accepted")
	}
}
