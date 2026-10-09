// Package http1 is a tiny HTTP/1.x server sitting on our userspace TCP.
//
// Mental model: TCP delivers a byte stream; HTTP is just decoding that stream
// for a request ending in \r\n\r\n, then writing a response and closing.
//
// It runs on any net.Listener / net.Conn: our TCP's Listener, a TLS conn
// on top of it, or a kernel socket. It deliberately leaves out keep-alive,
// request bodies, chunked encoding, header decoding beyond the request line,
// and routing: every path gets the same page.
package http1

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// maxBuf caps how many bytes we buffer per connection while waiting for
// the end of the headers. Without a cap, a client that never sends
// \r\n\r\n could make us buffer forever.
const maxBuf = 64 << 10

// Server serves the same tiny page on every connection it is given.
type Server struct {
	log  *log.Logger
	Body string // response body; default greeting if empty
}

// New returns a Server that logs to logger, or to the standard logger
// if logger is nil.
func New(logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{log: logger}
}

// Serve accepts connections on ln and handles each in its own goroutine.
// It returns when ln.Accept fails (for example after ln.Close).
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(c)
	}
}

// ServeConn reads one HTTP request from c, writes the response, and closes.
// It is what Go's net/http does per connection, only smaller.
//
// TCP is a byte stream, not a message stream. One request can arrive in
// several Reads, and segment boundaries mean nothing to HTTP. So bytes
// are appended to a buffer until the blank line that ends the header
// section (\r\n\r\n, RFC 9112 Section 2.1) shows up. Anything after it
// (a body, a pipelined request) is ignored; that is safe only because
// every response closes the connection.
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	var req []byte
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		req = append(req, buf[:n]...)
		if end := bytes.Index(req, []byte("\r\n\r\n")); end >= 0 {
			_, _ = c.Write(s.respond(c.RemoteAddr(), string(req[:end])))
			return
		}
		if len(req) > maxBuf {
			s.log.Printf("http: %v request too large — 413", c.RemoteAddr())
			_, _ = c.Write(s.response(413, "text/plain", "request too large\n"))
			return
		}
		if err != nil {
			if err != io.EOF {
				s.log.Printf("http: %v read: %v", c.RemoteAddr(), err)
			}
			return
		}
	}
}

// respond builds the reply to a request whose header section is head
// (everything before the blank line).
func (s *Server) respond(from net.Addr, head string) []byte {
	// The first line is the request line: "METHOD target HTTP/x.y"
	// (RFC 9112 Section 3). Only the method and target are used; the
	// version and all header fields are ignored.
	line, _, _ := strings.Cut(head, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 {
		s.log.Printf("http: %v bad request-line %q", from, line)
		return s.response(400, "text/plain", "bad request\n")
	}
	method, path := parts[0], parts[1]
	s.log.Printf("http: %v %s %s", from, method, path)

	// Only GET and HEAD are supported, and the path does not matter.
	switch method {
	case "GET", "HEAD":
		body := s.body()
		// HEAD gets the same headers as GET, including the Content-Length
		// GET would have had, but no body (RFC 9110 Section 9.3.2).
		if method == "HEAD" {
			return s.responseHead(200, "text/html; charset=utf-8", len(body))
		}
		return s.response(200, "text/html; charset=utf-8", body)
	default:
		return s.response(405, "text/plain", "method not allowed\n")
	}
}

// Handler returns an http.Handler that serves the same page as this
// Server. Pass it to net/http.Server to prove the stdlib works on our
// Listener unchanged.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			body := s.body()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, body)
			}
			s.log.Printf("http-go: %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		default:
			http.Error(w, "method not allowed\n", http.StatusMethodNotAllowed)
		}
	})
}

// body returns the page served for every GET: Body if set, otherwise a
// small built-in HTML greeting.
func (s *Server) body() string {
	if s.Body != "" {
		return s.Body
	}
	return `<!doctype html>
<html><head><title>mytcp</title></head>
<body>
<h1>mytcp</h1>
<p>HTTP/1 over userspace TCP on TAP.</p>
</body></html>
`
}

// response builds a complete HTTP response: status line, headers, the
// blank line that ends the headers, then the body.
//
// The headers are the minimum a client needs. Content-Type says how to
// display the body. Content-Length says where the body ends, so the client
// does not have to guess. Connection: close says this server does not keep
// connections alive: it sends one response and then closes TCP
// (RFC 9112 Section 9.6). The status line says HTTP/1.0, whose default is
// already one request per connection.
func (s *Server) response(code int, ctype, body string) []byte {
	reason := statusText(code)
	return []byte(fmt.Sprintf(
		"HTTP/1.0 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		code, reason, ctype, len(body), body,
	))
}

// responseHead builds the same headers as response for a body of bodyLen
// bytes, but without the body itself. It is used for HEAD requests.
func (s *Server) responseHead(code int, ctype string, bodyLen int) []byte {
	reason := statusText(code)
	return []byte(fmt.Sprintf(
		"HTTP/1.0 %d %s\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		code, reason, ctype, bodyLen,
	))
}

// statusText returns the reason phrase for the few status codes this
// server sends. Clients are expected to act on the number and ignore the
// phrase; it is there for humans reading the raw bytes.
func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 405:
		return "Method Not Allowed"
	case 413:
		return "Payload Too Large"
	default:
		return "Error"
	}
}
