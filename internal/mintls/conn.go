// Package mintls is a minimal, hand-written TLS 1.2 server, built for teaching.
//
// It speaks exactly one cipher suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// (0xC02B, RFC 5289). That means an ephemeral P-256 key exchange, an ECDSA
// certificate signature, AES-128-GCM for the records, and SHA-256 for the PRF.
// It sits on top of any net.Conn byte stream (here: our userspace TCP) and
// hands back a net.Conn that reads and writes plaintext. This package owns the
// record layer and the handshake state machine; the primitives (AES, GCM, ECDH,
// ECDSA, HMAC, SHA-256) come from the Go standard library.
//
// It deliberately leaves out almost everything else: no client mode, no TLS 1.3
// or older versions, no other cipher suites, no session resumption, no
// renegotiation, no client certificates, no extension negotiation, and no
// alerts of its own (it never sends one, and any alert it receives just ends
// the connection). Do not use it in production; use crypto/tls.
package mintls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"
)

// Config holds the server's certificate and key. Only Certificates[0] is used,
// and its key must be ECDSA P-256 because that is what our one cipher suite
// signs with.
type Config struct {
	Certificates []Certificate
}

// Certificate is a certificate chain in DER form plus the private key that
// matches the leaf certificate.
type Certificate struct {
	Certificate [][]byte // DER chain; [0] is the leaf, sent to the client in this order
	PrivateKey  *ecdsa.PrivateKey
}

// Conn is a server-side TLS 1.2 connection. After a successful Handshake,
// Read and Write move plaintext while the bytes on raw are encrypted records.
type Conn struct {
	raw net.Conn // the underlying byte stream (TCP)

	// TLS keys are one-directional: the client encrypts with the client
	// write key and we encrypt with the server write key. Each direction also
	// has its own sequence number, so we keep two independent halves.
	in  *halfConn // decrypts records the client sends us
	out *halfConn // encrypts records we send to the client

	mu     sync.Mutex
	rbuf   []byte // during the handshake: partial handshake bytes; afterwards: decrypted app data waiting for Read
	closed bool
}

// Server wraps raw in a mintls server Conn. No bytes are exchanged yet; the
// caller must call Handshake before Read or Write. The cfg argument is not
// stored here; Handshake takes its own cfg.
func Server(raw net.Conn, cfg *Config) *Conn {
	return &Conn{raw: raw}
}

// LocalAddr, RemoteAddr and the deadline methods simply delegate to the
// underlying connection, so that Conn satisfies net.Conn.

// LocalAddr returns the local address of the underlying connection.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr returns the remote address of the underlying connection.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline sets read and write deadlines on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// Handshake runs the full TLS 1.2 server handshake (RFC 5246 section 7.3) for
// ECDHE_ECDSA. It is one straight line of code, top to bottom, matching the
// message flow:
//
//	Client                                     Server (us)
//	------                                     -----------
//	ClientHello              -------->                        plaintext
//	                                           ServerHello
//	                                           Certificate
//	                                     ServerKeyExchange
//	                         <--------     ServerHelloDone    plaintext
//	ClientKeyExchange        -------->                        plaintext
//	  (both sides now compute pre-master -> master -> keys)
//	ChangeCipherSpec         -------->                        "client keys on"
//	Finished                 -------->                        encrypted
//	                         <--------    ChangeCipherSpec    "server keys on"
//	                         <--------            Finished    encrypted
//	Application Data         <------->    Application Data    encrypted
//
// Every handshake message (not ChangeCipherSpec, which is its own record type)
// is fed into a running SHA-256 "transcript hash". The two Finished messages
// prove that both sides saw exactly the same transcript.
func (c *Conn) Handshake(cfg *Config) error {
	if cfg == nil || len(cfg.Certificates) == 0 || cfg.Certificates[0].PrivateKey == nil {
		return fmt.Errorf("mintls: missing server certificate")
	}
	cert := cfg.Certificates[0]
	// hs is the transcript hash: SHA-256 over every handshake message, in
	// order, header included, as it went over the wire.
	hs := sha256.New()

	// --- ClientHello ---
	// The client proposes a version, its 32-byte random, and a list of
	// cipher suites. readHandshakePlain also adds it to the transcript.
	chBody, err := c.readHandshakePlain(hs)
	if err != nil {
		return err
	}
	if chBody[0] != hsClientHello {
		return fmt.Errorf("mintls: expected ClientHello, got %d", chBody[0])
	}
	// Skip the 4-byte handshake header: type(1) length(3).
	ch, err := decodeClientHello(chBody[4:])
	if err != nil {
		return err
	}
	// We have no negotiation: either the client offers our one suite, or we quit.
	if !ch.hasOurCipher {
		return fmt.Errorf("mintls: client did not offer ECDHE_ECDSA_AES_128_GCM_SHA256")
	}

	// --- ServerHello ---
	// Our 32 fresh random bytes. Both randoms go into every key derivation,
	// so even the same key exchange would never produce the same keys twice.
	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		return err
	}
	// We do not support resumption, so we always send an empty session ID
	// instead of echoing the client's. That tells the client "new session".
	sessionID := []byte{}

	// Pattern for each server message: build it, add it to the transcript,
	// and send it in its own plaintext handshake record.
	sh := encodeServerHello(serverRandom, sessionID)
	hs.Write(sh)
	if err := writeRecord(c.raw, recordHandshake, VersionTLS12, sh); err != nil {
		return err
	}

	// --- Certificate ---
	// Our certificate chain. The client uses it to learn our long-term
	// public key (and, with a real CA, to check who we are).
	certMsg := encodeCertificate(cert.Certificate)
	hs.Write(certMsg)
	if err := writeRecord(c.raw, recordHandshake, VersionTLS12, certMsg); err != nil {
		return err
	}

	// --- ServerKeyExchange ---
	// A brand new P-256 key pair just for this connection ("ephemeral").
	// We send the public half and keep the private half in memory only.
	// Once this function returns it is gone, so a later theft of the
	// certificate key cannot decrypt a recorded session: forward secrecy.
	ecdhe, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// The ephemeral public key is signed with the certificate key. That
	// proves we own the certificate and stops a man in the middle from
	// swapping in his own ECDHE key.
	ske, err := encodeServerKeyExchange(ch.random, serverRandom, ecdhe.PublicKey().Bytes(), cert.PrivateKey)
	if err != nil {
		return err
	}
	hs.Write(ske)
	if err := writeRecord(c.raw, recordHandshake, VersionTLS12, ske); err != nil {
		return err
	}

	// --- ServerHelloDone ---
	// An empty message that means "your turn".
	shd := encodeServerHelloDone()
	hs.Write(shd)
	if err := writeRecord(c.raw, recordHandshake, VersionTLS12, shd); err != nil {
		return err
	}

	// --- ClientKeyExchange + CCS + Finished ---
	// The client answers with its own ephemeral P-256 public key.
	ckeBody, err := c.readHandshakePlain(hs)
	if err != nil {
		return err
	}
	if ckeBody[0] != hsClientKeyExchange {
		return fmt.Errorf("mintls: expected ClientKeyExchange, got %d", ckeBody[0])
	}
	clientPubBytes, err := decodeClientKeyExchange(ckeBody[4:])
	if err != nil {
		return err
	}
	// NewPublicKey checks that the bytes are a valid point on P-256.
	// Accepting points off the curve enables the "invalid curve" attack.
	clientPub, err := ecdh.P256().NewPublicKey(clientPubBytes)
	if err != nil {
		return fmt.Errorf("mintls: client ECDHE pub: %w", err)
	}
	// ECDH: our private key times the client's public point. The client
	// computes its private key times our public point and gets the same
	// 32 bytes. This shared secret (the "pre-master secret") never crossed
	// the wire; an eavesdropper only saw the two public keys.
	preMaster, err := ecdhe.ECDH(clientPub)
	if err != nil {
		return err
	}
	// Stretch the pre-master secret into a 48-byte master secret, then into
	// the actual AES keys and nonce salts (see prf.go).
	master := masterSecret(preMaster, ch.random, serverRandom)
	clientKey, serverKey, clientIV, serverIV := keyBlock(master, ch.random, serverRandom)

	// Build both record ciphers now. Each starts with sequence number 0, and
	// no record has used them yet, so each direction's count effectively
	// starts at 0 right after its ChangeCipherSpec, as TLS requires.
	c.in, err = newGCM(clientKey, clientIV) // decrypts what the client writes
	if err != nil {
		return err
	}
	c.out, err = newGCM(serverKey, serverIV) // encrypts what we write
	if err != nil {
		return err
	}

	// ChangeCipherSpec (plaintext). This is its own record type (20) with a
	// single byte 0x01. It means "everything I send after this is encrypted".
	// It is not a handshake message, so it is not added to the transcript.
	typ, _, payload, err := readRecord(c.raw)
	if err != nil {
		return err
	}
	if typ != recordChangeCipherSpec || len(payload) != 1 || payload[0] != 1 {
		return fmt.Errorf("mintls: expected ChangeCipherSpec")
	}

	// Finished (encrypted). This is the first record under the client's new
	// keys. Just decrypting it already proves the client derived the same keys.
	finMsg, err := c.readHandshakeEncrypted(hs)
	if err != nil {
		return err
	}
	if finMsg[0] != hsFinished {
		return fmt.Errorf("mintls: expected Finished, got %d", finMsg[0])
	}
	// The client's verify_data is PRF(master, "client finished", hash of
	// all handshake messages so far). hs does not yet include the client's
	// Finished itself, which is exactly the input the client used.
	clientVerify := finishedVerify(master, "client finished", hs.Sum(nil))
	// If an attacker changed any handshake byte (for example, removed a
	// strong cipher suite from the ClientHello), the two transcripts differ
	// and so does this value.
	got := finMsg[4:]
	if !bytes.Equal(got, clientVerify) {
		return fmt.Errorf("mintls: bad client Finished")
	}
	// Our own Finished covers the client's Finished too, so add it now.
	hs.Write(finMsg)

	// Our CCS + Finished. After our CCS, everything we send is encrypted.
	if err := writeRecord(c.raw, recordChangeCipherSpec, VersionTLS12, []byte{1}); err != nil {
		return err
	}
	serverVerify := finishedVerify(master, "server finished", hs.Sum(nil))
	fin := encodeFinished(serverVerify)
	// The first record under our keys: sealed with sequence number 0.
	enc := c.out.seal(recordHandshake, VersionTLS12, fin)
	if err := writeRecord(c.raw, recordHandshake, VersionTLS12, enc); err != nil {
		return err
	}
	// Handshake done. Drop any leftover handshake bytes so rbuf can hold
	// application data from now on.
	c.rbuf = nil
	return nil
}

// readHandshakePlain returns the next complete handshake message (with its
// 4-byte header) from unencrypted records, and adds it to the transcript hash.
//
// Records and handshake messages are two separate layers. One record can
// carry several handshake messages, and one message can be split across
// several records. So we append record payloads to c.rbuf and cut out one
// message once enough bytes have arrived.
func (c *Conn) readHandshakePlain(hs hash.Hash) ([]byte, error) {
	for {
		typ, _, payload, err := readRecord(c.raw)
		if err != nil {
			return nil, err
		}
		// Before encryption is on, a client that dislikes our messages will
		// send a plaintext alert. We just report its raw bytes.
		if typ == recordAlert {
			return nil, fmt.Errorf("mintls: alert from peer: %v", payload)
		}
		if typ != recordHandshake {
			return nil, fmt.Errorf("mintls: unexpected record type %d", typ)
		}
		c.rbuf = append(c.rbuf, payload...)
		if msg, rest, ok := popHandshake(c.rbuf); ok {
			c.rbuf = rest
			hs.Write(msg)
			return msg, nil
		}
	}
}

// readHandshakeEncrypted is like readHandshakePlain, but each record is first
// decrypted and authenticated with the client's keys. Unlike
// readHandshakePlain, it does not add the message to the transcript hash: the
// caller has to check Finished against the hash before this message is added.
func (c *Conn) readHandshakeEncrypted(hs hash.Hash) ([]byte, error) {
	for {
		typ, vers, payload, err := readRecord(c.raw)
		if err != nil {
			return nil, err
		}
		if typ == recordAlert {
			return nil, fmt.Errorf("mintls: alert from peer")
		}
		if typ != recordHandshake {
			return nil, fmt.Errorf("mintls: unexpected encrypted type %d", typ)
		}
		// The record header's type and version are part of the GCM
		// additional data, so a tampered header fails decryption.
		plain, err := c.in.open(typ, vers, payload)
		if err != nil {
			return nil, err
		}
		c.rbuf = append(c.rbuf, plain...)
		if msg, rest, ok := popHandshake(c.rbuf); ok {
			c.rbuf = rest
			// The caller verifies Finished first, then writes msg to hs.
			_ = hs
			return msg, nil
		}
	}
}

// popHandshake cuts one complete handshake message off the front of buf.
// Every handshake message starts with a 4-byte header:
//
//	msg_type(1) length(3) body(length)
//
// The length is a 3-byte big-endian number. If buf does not yet hold the
// whole message, ok is false and buf is returned unchanged. The returned msg
// is a copy, so it stays valid when buf is reused.
func popHandshake(buf []byte) (msg, rest []byte, ok bool) {
	if len(buf) < 4 {
		return nil, buf, false
	}
	n := uint24(buf[1:4])
	if len(buf) < 4+n {
		return nil, buf, false
	}
	msg = append([]byte{}, buf[:4+n]...)
	return msg, buf[4+n:], true
}

// Read returns decrypted application data. If none is buffered, it reads
// whole records from the network, checks and decrypts each one, and buffers
// the plaintext. Any alert from the peer (for example close_notify) is
// treated as end of stream.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	for len(c.rbuf) == 0 {
		typ, vers, payload, err := readRecord(c.raw)
		if err != nil {
			return 0, err
		}
		switch typ {
		case recordAlert:
			// After the handshake, alerts are encrypted too. We do not
			// decrypt them; any alert just ends the stream.
			c.closed = true
			return 0, io.EOF
		case recordApplicationData:
			// open fails if even one bit of the record was changed.
			plain, err := c.in.open(typ, vers, payload)
			if err != nil {
				return 0, err
			}
			c.rbuf = append(c.rbuf, plain...)
		case recordHandshake:
			// A post-handshake handshake message (for example a
			// renegotiation request). We still decrypt it, because that
			// advances the client's sequence number, and then ignore it.
			if _, err := c.in.open(typ, vers, payload); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("mintls: unexpected type %d", typ)
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// Write encrypts p and sends it as one or more application_data records.
// It returns the number of plaintext bytes sent.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.out == nil {
		return 0, fmt.Errorf("mintls: Write before Handshake")
	}
	// Split into records of at most 4096 plaintext bytes (TLS allows up to
	// 16384). Each record gets its own sequence number and nonce.
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 4096 {
			n = 4096
		}
		enc := c.out.seal(recordApplicationData, VersionTLS12, p[:n])
		if err := writeRecord(c.raw, recordApplicationData, VersionTLS12, enc); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close closes the underlying connection. It does not send a close_notify
// alert first, so the peer just sees the TCP stream end.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.raw.Close()
}
