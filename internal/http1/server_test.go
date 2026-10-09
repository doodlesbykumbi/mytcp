package http1_test

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/http1"
)

// pipePair is an in-memory net.Conn with TCP-looking addresses.
type pipePair struct {
	net.Conn
	local, remote net.Addr
}

func (p pipePair) LocalAddr() net.Addr  { return p.local }
func (p pipePair) RemoteAddr() net.Addr { return p.remote }

// roundTrip runs ServeConn on one end of a pipe, writes each chunk as a
// separate Write (like separate TCP segments), and returns everything the
// server sent before closing.
func roundTrip(t *testing.T, chunks ...string) string {
	t.Helper()
	s := http1.New(log.New(io.Discard, "", 0))
	c1, client := net.Pipe()
	go s.ServeConn(pipePair{
		Conn:   c1,
		local:  &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 80},
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 50000},
	})
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	for _, c := range chunks {
		if _, err := client.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestGET(t *testing.T) {
	got := roundTrip(t, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	for _, want := range []string{"HTTP/1.0 200", "mytcp", "Connection: close"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestPartialThenComplete(t *testing.T) {
	got := roundTrip(t, "GET / HTTP/1.1\r\n", "Host: x\r\n\r\n")
	if !strings.HasPrefix(got, "HTTP/1.0 200") {
		t.Fatalf("got %q", got)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	if got := roundTrip(t, "POST / HTTP/1.0\r\n\r\n"); !strings.Contains(got, "405") {
		t.Fatalf("got %q", got)
	}
}

func TestStdlibHandler(t *testing.T) {
	s := http1.New(log.New(io.Discard, "", 0))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: s.Handler()}
	srv.SetKeepAlivesEnabled(false)
	go srv.Serve(ln)

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "mytcp") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}
