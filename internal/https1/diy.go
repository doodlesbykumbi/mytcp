package https1

import (
	"log"
	"net"

	"github.com/doodlesbykumbi/mytcp/internal/http1"
	"github.com/doodlesbykumbi/mytcp/internal/mintls"
)

// DIYServer is HTTPS using our own TLS 1.2 stack (mintls), not crypto/tls.
//
// The plumbing is the same as Server; only the middle layer changes.
// mintls speaks only TLS 1.2 with one cipher suite
// (ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), so clients have to be told to
// cap at TLS 1.2 (curl --tls-max 1.2).
type DIYServer struct {
	cfg  *mintls.Config
	http *http1.Server
	log  *log.Logger
}

// NewDIY builds a mintls-backed HTTPS server with an ephemeral self-signed cert.
func NewDIY(ip net.IP, logger *log.Logger) (*DIYServer, error) {
	if logger == nil {
		logger = log.Default()
	}
	// mintls makes its own certificate and ECDSA key, so this variant does
	// not depend on crypto/tls anywhere.
	der, key, err := mintls.SelfSigned(ip.To4(), []string{"localhost", "mytcp.local"})
	if err != nil {
		return nil, err
	}
	return &DIYServer{
		cfg: &mintls.Config{Certificates: []mintls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}}},
		http: http1.New(logger),
		log:  logger,
	}, nil
}

// Serve accepts connections on ln and serves each in its own goroutine.
// It returns when ln.Accept fails (for example after ln.Close).
func (s *DIYServer) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serve(c)
	}
}

// serve runs one HTTPS connection from handshake to close, using mintls.
func (s *DIYServer) serve(raw net.Conn) {
	// mintls needs an explicit Handshake before Read or Write. crypto/tls
	// would run it on first use; mintls has no such shortcut.
	tlsConn := mintls.Server(raw, s.cfg)
	if err := tlsConn.Handshake(s.cfg); err != nil {
		s.log.Printf("https-diy: handshake %v: %v", raw.RemoteAddr(), err)
		_ = raw.Close()
		return
	}
	s.log.Printf("https-diy: handshake ok %v (mintls TLS 1.2 ECDHE_ECDSA_AES_128_GCM)", raw.RemoteAddr())

	// mintls.Conn is a net.Conn too. Its Close closes the TCP stream
	// (sending our FIN) without a TLS close_notify alert first.
	s.http.ServeConn(tlsConn)
}
