package dns

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestQueryBytes(t *testing.T) {
	got, err := Query(0x1234, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1 question, no records
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Query =\n% x\nwant\n% x", got, want)
	}
}

func TestQueryRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "a..b", strings.Repeat("x", 64) + ".com", strings.Repeat("abcdefghi.", 26) + "com"} {
		if _, err := Query(1, name); err == nil {
			t.Errorf("Query(%.20q…) accepted", name)
		}
	}
}

// cnameResponse answers www.example.com with a CNAME to edge.example.com
// and an A record for that, both names written with compression pointers.
func cnameResponse() []byte {
	b := []byte{
		0x12, 0x34, 0x81, 0x80, // ID, flags: QR RD RA, rcode 0
		0, 1, 0, 2, 0, 0, 0, 0, // 1 question, 2 answers
		// offset 12: the question name
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
		// offset 33: CNAME, name = pointer to 12
		0xc0, 12, 0, 5, 0, 1, 0, 0, 1, 0x2c, 0, 7,
		// offset 45: "edge" then a pointer to "example.com" at 16
		4, 'e', 'd', 'g', 'e', 0xc0, 16,
		// offset 52: A, name = pointer to 45 (edge.example.com)
		0xc0, 45, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4,
		93, 184, 215, 14,
	}
	return b
}

func TestParseCNAMEChain(t *testing.T) {
	ips, err := ParseResponse(cnameResponse(), 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.215.14" {
		t.Fatalf("ips = %v", ips)
	}
	if name, err := readName(cnameResponse(), 52); err != nil || name != "edge.example.com" {
		t.Fatalf("readName = %q, %v", name, err)
	}
	if d := Describe(cnameResponse()); d != "answer id=4660 www.example.com → 93.184.215.14 (1 A)" {
		t.Fatalf("Describe = %q", d)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseResponse(cnameResponse(), 0x9999); err == nil {
		t.Error("wrong ID accepted")
	}

	nx := cnameResponse()[:33]
	nx[3] = 0x83 // rcode 3
	nx[7] = 0    // no answers
	if _, err := ParseResponse(nx, 0x1234); !errors.Is(err, ErrNotFound) {
		t.Errorf("NXDOMAIN: %v", err)
	}

	tc := cnameResponse()
	tc[2] |= 0x02 // TC
	if _, err := ParseResponse(tc, 0x1234); err == nil {
		t.Error("truncated answer accepted")
	}

	loop := cnameResponse()
	loop[33], loop[34] = 0xc0, 33 // the CNAME's name points at itself
	if _, err := ParseResponse(loop, 0x1234); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("pointer loop: %v", err)
	}

	full := cnameResponse()
	for n := 0; n < len(full); n++ {
		if _, err := ParseResponse(full[:n], 0x1234); err == nil {
			t.Errorf("accepted the first %d bytes only", n)
		}
	}
}
