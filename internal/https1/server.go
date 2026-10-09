// Package https1 serves HTTP/1 over TLS on our userspace TCP.
//
// Each server takes a net.Listener (our tcp.Listener in practice), wraps
// every accepted net.Conn in TLS, and hands the decrypted conn to the
// same http1.Server that serves plain HTTP:
//
//	TCP segments ⇄ tcp.StreamConn (net.Conn) ⇄ TLS conn (net.Conn) ⇄ http1.Server.ServeConn
//
// TLS needs a blocking Read/Write byte stream, which is exactly what a
// net.Conn is. Server uses Go's crypto/tls (TLS 1.2 or 1.3). DIYServer in
// diy.go uses our own mintls (TLS 1.2, one cipher suite). Certificates are
// generated at startup and self-signed, so clients must skip verification
// (curl -k).
package https1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/http1"
)

// Server is HTTPS using Go's crypto/tls.
type Server struct {
	cfg  *tls.Config
	http *http1.Server
	log  *log.Logger
}

// New builds a crypto/tls server with an ephemeral self-signed cert for ip.
func New(ip net.IP, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	cert, err := selfSigned(ip)
	if err != nil {
		return nil, err
	}
	// MinVersion refuses the deprecated TLS 1.0 and 1.1. crypto/tls picks
	// the highest version both sides support, so modern clients get 1.3.
	return &Server{
		cfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		http: http1.New(logger),
		log:  logger,
	}, nil
}

// TLSConfig returns the server's crypto/tls config (self-signed cert,
// TLS 1.2 minimum), for use with tls.NewListener.
func (s *Server) TLSConfig() *tls.Config { return s.cfg }

// Serve accepts connections on ln and serves each in its own goroutine.
// It returns when ln.Accept fails (for example after ln.Close).
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serve(c)
	}
}

// serve runs one HTTPS connection from TLS handshake to close.
func (s *Server) serve(raw net.Conn) {
	// tls.Server only needs a net.Conn. It has no idea the bytes travel
	// over a TCP written in userspace.
	tlsConn := tls.Server(raw, s.cfg)

	// The handshake is several round trips of TLS records over the same
	// conn: hello messages, certificate, key exchange, Finished.
	if err := tlsConn.Handshake(); err != nil {
		s.log.Printf("https: handshake %v: %v", raw.RemoteAddr(), err)
		_ = raw.Close()
		return
	}
	s.log.Printf("https: handshake ok %v %s", raw.RemoteAddr(), tls.VersionName(tlsConn.ConnectionState().Version))

	// From here the TLS conn is just another net.Conn: Read decrypts,
	// Write encrypts. ServeConn's Close sends close_notify, then closes
	// the TCP stream, which sends our FIN.
	s.http.ServeConn(tlsConn)
}

// selfSigned creates a fresh ECDSA P-256 key and a certificate for ip
// signed by that same key. Nothing trusts it, which is fine for a demo:
// the connection is still encrypted, just not authenticated.
func selfSigned(ip net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Serial numbers should be unique per issuer; a random one is the
	// usual approach for throwaway certificates.
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	// NotBefore is backdated an hour so small clock differences between us
	// and the client do not make the certificate "not yet valid". Clients
	// match the name they connected to against IPAddresses and DNSNames,
	// so those list our IP and the host names the demo might use.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip.To4()},
		DNSNames:     []string{"localhost", "mytcp.local"},
	}
	if ip4 := ip.To4(); ip4 != nil {
		tmpl.IPAddresses = []net.IP{ip4}
	}
	// Passing tmpl as both the certificate and its parent is what makes
	// it self-signed: subject and issuer are the same.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	// tls.X509KeyPair takes PEM text, so encode the DER bytes as PEM and
	// let it parse them back into a tls.Certificate.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
