package icmp_test

import (
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/icmp"
	"github.com/doodlesbykumbi/mytcp/internal/ip4"
)

func TestEchoReplyChecksum(t *testing.T) {
	req := icmp.Echo{Type: icmp.TypeEcho, ID: 7, Seq: 3, Payload: []byte("ping")}
	rep := icmp.ReplyFrom(req)
	raw := rep.Encode()
	if raw[0] != icmp.TypeEchoReply {
		t.Fatalf("type=%d", raw[0])
	}
	if sum := ip4.Checksum(raw); sum != 0 {
		t.Fatalf("icmp checksum residual %04x", sum)
	}
}
