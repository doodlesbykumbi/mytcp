package tcp_test

import (
	"net"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/tcp"
)

func TestSegmentChecksum(t *testing.T) {
	src := net.IPv4(10, 0, 0, 2)
	dst := net.IPv4(10, 0, 0, 1)
	seg := tcp.Segment{
		SrcPort: 7,
		DstPort: 12345,
		Seq:     1000,
		Ack:     2000,
		Flags:   tcp.FlagSYN | tcp.FlagACK,
		Window:  65535,
	}
	raw := seg.Encode(src, dst)
	got, err := tcp.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != seg.Seq || got.Ack != seg.Ack || got.Flags != seg.Flags {
		t.Fatalf("got %+v", got)
	}
	// verify checksum via pseudo-header
	pseudo := make([]byte, 12+len(raw))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = ip4.ProtoTCP
	pseudo[10] = byte(len(raw) >> 8)
	pseudo[11] = byte(len(raw))
	copy(pseudo[12:], raw)
	if sum := ip4.Checksum(pseudo); sum != 0 {
		t.Fatalf("tcp checksum residual %04x", sum)
	}
}
