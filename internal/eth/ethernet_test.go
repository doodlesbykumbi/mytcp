package eth_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/doodlesbykumbi/mytcp/internal/eth"
)

func TestDecodeEncodeRoundTrip(t *testing.T) {
	f := eth.Frame{
		Dst:     net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Src:     net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		Type:    eth.TypeARP,
		Payload: []byte{1, 2, 3, 4},
	}
	raw := f.Encode()
	got, err := eth.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Dst, f.Dst) || !bytes.Equal(got.Src, f.Src) || got.Type != f.Type {
		t.Fatalf("header mismatch: %+v", got)
	}
	if !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("payload %v != %v", got.Payload, f.Payload)
	}
}

func TestDecodeTooShort(t *testing.T) {
	if _, err := eth.Decode(make([]byte, 13)); err == nil {
		t.Fatal("expected error")
	}
}
