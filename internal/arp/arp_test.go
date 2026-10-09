package arp_test

import (
	"net"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
)

func TestReplyFor(t *testing.T) {
	req := arp.Packet{
		Op:  arp.OpRequest,
		SHA: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		SPA: net.IPv4(10, 0, 0, 1),
		THA: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		TPA: net.IPv4(10, 0, 0, 2),
	}
	ourMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	ourIP := net.IPv4(10, 0, 0, 2)
	rep := arp.ReplyFor(req, ourMAC, ourIP)
	if rep.Op != arp.OpReply {
		t.Fatalf("op=%d", rep.Op)
	}
	raw := rep.Encode()
	got, err := arp.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SPA.Equal(ourIP) || !got.TPA.Equal(req.SPA) {
		t.Fatalf("addrs spa=%s tpa=%s", got.SPA, got.TPA)
	}
}
