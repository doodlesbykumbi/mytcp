package capture_test

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/capture"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "sess")
	rec, err := capture.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x01,
	}
	if err := rec.Write(capture.RX, frame); err != nil {
		t.Fatal(err)
	}
	if err := rec.Write(capture.TX, frame); err != nil {
		t.Fatal(err)
	}
	_ = rec.Close()

	j, err := os.ReadFile(base + ".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(j) < 10 {
		t.Fatalf("jsonl too short: %s", j)
	}

	p, err := os.ReadFile(base + ".pcap")
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(p[0:4]) != 0xa1b2c3d4 {
		t.Fatalf("bad magic")
	}
	// header 24 + pkt hdr 16 + frame
	if len(p) < 24+16+len(frame) {
		t.Fatalf("pcap short %d", len(p))
	}
	got := p[24+16 : 24+16+len(frame)]
	if hex.EncodeToString(got) != hex.EncodeToString(frame) {
		t.Fatalf("frame mismatch")
	}
}
