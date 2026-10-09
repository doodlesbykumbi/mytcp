package ip4_test

import (
	"net"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

func TestChecksumKnown(t *testing.T) {
	// Empty buffer checksum is 0xffff
	if g := ip4.Checksum(nil); g != 0xffff {
		t.Fatalf("empty checksum=%04x", g)
	}
}

func TestEncodeDecode(t *testing.T) {
	p := ip4.Packet{
		ID:      0xabcd,
		TTL:     64,
		Proto:   ip4.ProtoICMP,
		Src:     net.IPv4(10, 0, 0, 2),
		Dst:     net.IPv4(10, 0, 0, 1),
		Payload: []byte{8, 0, 0, 0, 0, 1, 0, 1, 'h', 'i'},
	}
	raw := p.Encode()
	// header checksum should verify to 0 when included
	if sum := ip4.Checksum(raw[:20]); sum != 0 {
		t.Fatalf("header checksum residual %04x", sum)
	}
	got, err := ip4.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Proto != ip4.ProtoICMP || !got.Src.Equal(p.Src) || !got.Dst.Equal(p.Dst) {
		t.Fatalf("got %+v", got)
	}
}
