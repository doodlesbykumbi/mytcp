package dump_test

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/arp"
	"github.com/doodlesbykumbi/mytcp/internal/dns"
	"github.com/doodlesbykumbi/mytcp/internal/dump"
	"github.com/doodlesbykumbi/mytcp/internal/eth"
	"github.com/doodlesbykumbi/mytcp/internal/icmp"
	"github.com/doodlesbykumbi/mytcp/internal/ip4"
	"github.com/doodlesbykumbi/mytcp/internal/tcp"
	"github.com/doodlesbykumbi/mytcp/internal/udp"
)

func TestOnionTCP(t *testing.T) {
	seg := tcp.Segment{
		SrcPort: 7, DstPort: 1234, Seq: 1000, Ack: 2000,
		Flags: tcp.FlagACK | tcp.FlagPSH, Window: 65535,
		Payload: []byte("ok\n"),
	}
	src, dst := net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1)
	ip := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoTCP, Src: src, Dst: dst,
		Payload: seg.Encode(src, dst),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Type: eth.TypeIPv4, Payload: ip.Encode(),
	}

	var buf bytes.Buffer
	dump.Frame(&buf, ">>> TX", frame.Encode())
	out := buf.String()
	for _, want := range []string{
		"full frame",
		"layers",
		"L2 Ethernet",
		"L3 IPv4",
		"proto=TCP",
		"L4 TCP",
		"PSH,ACK",
		`payload     "ok\n"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestOnionARP(t *testing.T) {
	req := arp.Packet{
		Op:  arp.OpRequest,
		SHA: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		SPA: net.IPv4(10, 0, 0, 1),
		THA: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		TPA: net.IPv4(10, 0, 0, 2),
	}
	frame := eth.Frame{
		Dst: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src: req.SHA, Type: eth.TypeARP, Payload: req.Encode(),
	}
	var buf bytes.Buffer
	dump.Frame(&buf, "<<< RX", frame.Encode())
	if !strings.Contains(buf.String(), "who-has") {
		t.Fatal(buf.String())
	}
}

func TestOnionICMP(t *testing.T) {
	echo := icmp.Echo{Type: icmp.TypeEcho, ID: 1, Seq: 2, Payload: []byte("hi")}
	ip := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoICMP,
		Src: net.IPv4(10, 0, 0, 1), Dst: net.IPv4(10, 0, 0, 2),
		Payload: echo.Encode(),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Type: eth.TypeIPv4, Payload: ip.Encode(),
	}
	var buf bytes.Buffer
	dump.Frame(&buf, "<<< RX", frame.Encode())
	out := buf.String()
	if !strings.Contains(out, "echo-request") || !strings.Contains(out, "L4 ICMP") {
		t.Fatal(out)
	}
}

func TestOnionDNS(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 2), net.IPv4(1, 1, 1, 1)
	q, err := dns.Query(7, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	ip := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoUDP, Src: src, Dst: dst,
		Payload: udp.Datagram{SrcPort: 49152, DstPort: 53, Payload: q}.Encode(src, dst),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Type: eth.TypeIPv4, Payload: ip.Encode(),
	}
	var buf bytes.Buffer
	dump.Frame(&buf, ">>> TX", frame.Encode())
	out := buf.String()
	if !strings.Contains(out, "L4 UDP      49152 → 53") || !strings.Contains(out, "L7 DNS      query id=7 example.com") {
		t.Fatal(out)
	}
}

func TestOnionHTTP(t *testing.T) {
	body := "<!doctype html>\n<html>hi</html>\n"
	payload := []byte(
		"HTTP/1.0 200 OK\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: 28\r\n" +
			"Connection: close\r\n" +
			"\r\n" + body,
	)
	seg := tcp.Segment{
		SrcPort: 80, DstPort: 50840, Seq: 1001, Ack: 2000,
		Flags: tcp.FlagACK | tcp.FlagPSH, Window: 65535,
		Payload: payload,
	}
	src, dst := net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 1)
	ip := ip4.Packet{
		TTL: 64, Proto: ip4.ProtoTCP, Src: src, Dst: dst,
		Payload: seg.Encode(src, dst),
	}
	frame := eth.Frame{
		Dst:  net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		Src:  net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		Type: eth.TypeIPv4, Payload: ip.Encode(),
	}
	var buf bytes.Buffer
	dump.Frame(&buf, ">>> TX", frame.Encode())
	out := buf.String()
	for _, want := range []string{
		"L7 HTTP     HTTP/1.0 200 OK",
		"Content-Type: text/html",
		"body",
		"<!doctype html>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, `payload     "HTTP`) {
		t.Fatal("should not use raw payload line for HTTP")
	}
}
