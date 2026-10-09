package stack_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/dns"
	"github.com/doodlesbykumbi/mytcp/internal/stack"
)

// wire is one end of a virtual cable: frames written here are handed to
// the stack on the other end by a pump goroutine. Delivering them inline
// would deadlock, since a stack writes while holding its TCP lock.
type wire struct {
	out  chan []byte
	done chan struct{}
}

func newWire() *wire { return &wire{out: make(chan []byte, 256), done: make(chan struct{})} }

func (w *wire) Name() string             { return "wire" }
func (w *wire) Read([]byte) (int, error) { return 0, io.EOF }
func (w *wire) Write(p []byte) (int, error) {
	select {
	case w.out <- append([]byte(nil), p...):
	case <-w.done:
	}
	return len(p), nil
}

func pump(t *testing.T, from *wire, to *stack.Stack) {
	go func() {
		for {
			select {
			case f := <-from.out:
				_ = to.HandleFrame(f)
			case <-from.done:
				return
			}
		}
	}()
	t.Cleanup(func() { close(from.done) })
}

// cabled returns a client stack (10.0.0.2) and a server stack (10.0.0.1)
// on one link, each knowing nothing about the other until ARP.
func cabled(t *testing.T) (client, server *stack.Stack) {
	quiet := log.New(io.Discard, "", 0)
	cw, sw := newWire(), newWire()
	client = stack.New(cw, stack.Config{
		MAC: ourMAC, IP: ourIP, Subnet: lan, Gateway: gwIP, DNS: gwIP,
		ARPRetry: 50 * time.Millisecond, Logger: quiet,
	})
	server = stack.New(sw, stack.Config{MAC: gwMAC, IP: gwIP, Logger: quiet})
	pump(t, cw, server)
	pump(t, sw, client)
	return client, server
}

func TestDialContextEcho(t *testing.T) {
	client, server := cabled(t)
	ln := server.TCP().Listen(7)
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", "10.0.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestDialContextRefused(t *testing.T) {
	client, _ := cabled(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := client.DialContext(ctx, "tcp", "10.0.0.1:8")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want connection refused", err)
	}
}

func TestDialContextRejectsUDP(t *testing.T) {
	client, _ := cabled(t)
	if _, err := client.DialContext(context.Background(), "udp", "10.0.0.1:53"); err == nil {
		t.Fatal("udp dial succeeded")
	}
}

// fakeDNS answers every A query on server's UDP port 53: names ending in
// ".test" are at the server's own address, anything else is NXDOMAIN.
func fakeDNS(t *testing.T, server *stack.Stack) {
	u, err := server.BindUDP(53)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	go func() {
		for {
			q, ip, port, err := u.ReadFrom(context.Background())
			if err != nil {
				return
			}
			a := append([]byte(nil), q...)
			if strings.Contains(string(q), "\x04test\x00") {
				binary.BigEndian.PutUint16(a[2:4], 0x8180)
				binary.BigEndian.PutUint16(a[6:8], 1)
				// Name: a pointer to the question's name at offset 12.
				a = append(a, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				a = append(a, gwIP.To4()...)
			} else {
				binary.BigEndian.PutUint16(a[2:4], 0x8183)
			}
			_ = u.WriteTo(context.Background(), a, ip, port)
		}
	}()
}

func TestDialContextByName(t *testing.T) {
	client, server := cabled(t)
	fakeDNS(t, server)
	ln := server.TCP().Listen(7)
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.DialContext(ctx, "tcp", "echo.test:7")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.RemoteAddr().String(); got != "10.0.0.1:7" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	if _, err := c.Write([]byte("by-name")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "by-name" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestLookupNotFound(t *testing.T) {
	client, server := cabled(t)
	fakeDNS(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.LookupIPv4(ctx, "nowhere.example"); !errors.Is(err, dns.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if _, err := client.DialContext(ctx, "tcp", "echo.test:http"); err == nil {
		t.Fatal("named port accepted")
	}
}
