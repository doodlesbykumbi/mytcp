package mintls

import (
	"math/rand"
	"testing"
)

// A ClientHello body: version 3,3; 32-byte random; empty session_id;
// one cipher suite (ours); one compression method (null).
func validClientHello() []byte {
	b := []byte{3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)          // session_id length
	b = append(b, 0, 2)       // cipher_suites length
	b = append(b, 0xC0, 0x2B) // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	b = append(b, 1, 0)       // compression: one method, null
	return b
}

func TestDecodeClientHelloValid(t *testing.T) {
	ch, err := decodeClientHello(validClientHello())
	if err != nil {
		t.Fatal(err)
	}
	if !ch.hasOurCipher {
		t.Fatal("expected our cipher suite to be found")
	}
}

// Every truncation of a valid hello must be an error, never a panic: the
// bytes come straight from the network.
func TestDecodeClientHelloTruncated(t *testing.T) {
	full := validClientHello()
	for n := 0; n < len(full); n++ {
		if _, err := decodeClientHello(full[:n]); err == nil {
			t.Errorf("len %d: expected an error", n)
		}
	}
}

func TestDecodeClientHelloGarbage(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.Intn(80))
		r.Read(b)
		decodeClientHello(b) // must not panic
	}
}
