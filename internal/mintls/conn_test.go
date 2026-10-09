package mintls

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func errString(s string) error { return errors.New(s) }

func TestHandshakeAndHTTPRoundTrip(t *testing.T) {
	certDER, key, err := SelfSigned(net.IPv4(10, 0, 0, 2), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Certificates: []Certificate{{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}}}

	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer c1.Close()
		srv := Server(c1, cfg)
		if err := srv.Handshake(cfg); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 256)
		n, err := srv.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if string(buf[:n]) != "ping" {
			errCh <- errString("want ping, got " + string(buf[:n]))
			return
		}
		_, err = srv.Write([]byte("pong"))
		errCh <- err
	}()

	client := tls.Client(c2, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	defer c2.Close()

	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("client read: %v (server err: %v)", err, <-errCh)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("got %q", buf[:n])
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
