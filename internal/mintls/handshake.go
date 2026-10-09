package mintls

// This file turns handshake messages into bytes and back. All multi-byte
// numbers in TLS are big-endian (most significant byte first). Variable-length
// fields carry a length prefix in front of them; the prefix is 1, 2 or 3 bytes
// wide depending on how large the field may get. In the layouts below, the
// number in parentheses is the field size in bytes.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"time"
)

// putUint24 writes n into b[0:3] as a 3-byte big-endian number. TLS uses
// 3-byte lengths for handshake messages and certificates (up to 16 MiB).
func putUint24(b []byte, n int) {
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
}

// uint24 reads a 3-byte big-endian number from b[0:3].
func uint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// encodeHandshake wraps body in the 4-byte handshake header that every
// handshake message starts with (RFC 5246 section 7.4):
//
//	msg_type(1) length(3) body(length)
//
// These exact bytes are what go into the transcript hash.
func encodeHandshake(typ byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = typ
	putUint24(out[1:4], len(body))
	copy(out[4:], body)
	return out
}

// clientHello holds the ClientHello fields this server cares about.
type clientHello struct {
	random       []byte   // 32 bytes chosen by the client; mixed into every key
	sessionID    []byte   // decoded but unused; we never resume sessions
	cipherSuites []uint16 // everything the client offered
	hasOurCipher bool     // true if 0xC02B is in cipherSuites
}

// decodeClientHello decodes a ClientHello body (the bytes after the 4-byte
// handshake header). The layout (RFC 5246 section 7.4.1.2) is:
//
//	client_version(2)
//	random(32)
//	session_id_len(1)       session_id(session_id_len)
//	cipher_suites_len(2)    cipher_suites(cipher_suites_len), 2 bytes each
//	compression_len(1)      compression_methods(compression_len)
//	extensions...           (ignored here)
//
// Before slicing with a length field, we check it against the bytes that are
// left, so a lying length returns an error instead of reading past the end.
func decodeClientHello(body []byte) (*clientHello, error) {
	// client_version(2) + random(32) + the session_id length byte(1)
	if len(body) < 35 {
		return nil, fmt.Errorf("mintls: ClientHello too short")
	}
	off := 2 // skip client_version; we only ever speak TLS 1.2
	random := append([]byte{}, body[off:off+32]...)
	off += 32
	// session_id: 1-byte length prefix (the spec allows up to 32 bytes).
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return nil, fmt.Errorf("mintls: bad session_id")
	}
	sid := append([]byte{}, body[off:off+sidLen]...)
	off += sidLen
	// cipher_suites: 2-byte length prefix, then a list of 2-byte suite IDs.
	if off+2 > len(body) {
		return nil, fmt.Errorf("mintls: bad cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(body) {
		return nil, fmt.Errorf("mintls: bad cipher suites len")
	}
	var suites []uint16
	has := false
	// The client lists suites in order of preference. We only look for ours.
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(body[off+i : off+i+2])
		suites = append(suites, cs)
		if cs == CipherECDHE_ECDSA_AES128_GCM_SHA256 {
			has = true
		}
	}
	off += csLen
	// compression_methods: 1-byte length prefix. We check that it is well
	// formed but do not look at it; we always choose "null" (no compression).
	if off >= len(body) {
		return nil, fmt.Errorf("mintls: missing compression")
	}
	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return nil, fmt.Errorf("mintls: bad compression")
	}
	off += compLen
	// Anything after this point is extensions (SNI, supported curves,
	// signature algorithms, ...). We skip them all and simply assume the
	// client can handle P-256 and ECDSA with SHA-256.
	return &clientHello{random: random, sessionID: sid, cipherSuites: suites, hasOurCipher: has}, nil
}

// encodeServerHello builds the ServerHello message, which fixes the choices
// for this connection (RFC 5246 section 7.4.1.3):
//
//	server_version(2)=0x0303
//	random(32)
//	session_id_len(1)     session_id
//	cipher_suite(2)=0xC02B
//	compression_method(1)=0
//	extensions_len(2)     extensions
//
// It returns the full message including the 4-byte handshake header.
func encodeServerHello(random, sessionID []byte) []byte {
	body := make([]byte, 0, 2+32+1+len(sessionID)+2+1+2+32)
	body = append(body, byte(VersionTLS12>>8), byte(VersionTLS12&0xff))
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, byte(CipherECDHE_ECDSA_AES128_GCM_SHA256>>8), byte(CipherECDHE_ECDSA_AES128_GCM_SHA256&0xff))
	body = append(body, 0) // null compression
	// Each extension is: type(2) length(2) data(length).
	ext := []byte{
		// renegotiation_info (0xff01, RFC 5746): data is a 1-byte length
		// of 0, meaning "fresh connection, no previous handshake".
		0xff, 0x01, 0x00, 0x01, 0x00, // renegotiation_info
		// ec_point_formats (0x000b, RFC 8422): a 1-byte list length of 1
		// holding format 0, "uncompressed" points.
		0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return encodeHandshake(hsServerHello, body)
}

// encodeCertificate builds the Certificate message (RFC 5246 section 7.4.2).
// It is a list inside a list, both with 3-byte length prefixes:
//
//	certificate_list_len(3)
//	  cert_len(3) cert(DER)     leaf first
//	  cert_len(3) cert(DER)     then any intermediates
//	  ...
func encodeCertificate(ders [][]byte) []byte {
	var certsLen int
	for _, d := range ders {
		certsLen += 3 + len(d) // each entry carries its own 3-byte length
	}
	body := make([]byte, 3+certsLen)
	putUint24(body[0:3], certsLen)
	off := 3
	for _, d := range ders {
		putUint24(body[off:off+3], len(d))
		off += 3
		copy(body[off:], d)
		off += len(d)
	}
	return encodeHandshake(hsCertificate, body)
}

// encodeServerHelloDone builds ServerHelloDone (RFC 5246 section 7.4.5):
// just the 4-byte header with an empty body, meaning "the client may answer now".
func encodeServerHelloDone() []byte {
	return encodeHandshake(hsServerHelloDone, nil)
}

// encodeServerKeyExchange builds the ServerKeyExchange message for ECDHE
// (RFC 8422 section 5.4). It carries our ephemeral public key, signed with the
// certificate's private key:
//
//	curve_type(1)=3          "named_curve"
//	named_curve(2)=23        secp256r1, also known as P-256
//	pubkey_len(1)=65
//	pubkey(65)               0x04 || X(32) || Y(32), an uncompressed point
//	sig_alg(2)=0x0403        hash 4 = SHA-256, signature 3 = ECDSA
//	sig_len(2)
//	sig(sig_len)             DER-encoded ECDSA signature
//
// The signature covers client_random || server_random || params, where params
// is the first four fields above. Signing the ephemeral key proves that the
// holder of the certificate key chose it. Including both randoms binds the
// signature to this one handshake, so an attacker cannot replay it later.
func encodeServerKeyExchange(clientRandom, serverRandom, ecdhePub []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	params := make([]byte, 0, 4+len(ecdhePub))
	params = append(params, 3) // named_curve
	params = append(params, byte(curvesecp256r1>>8), byte(curvesecp256r1))
	params = append(params, byte(len(ecdhePub)))
	params = append(params, ecdhePub...)

	// What we sign: 32 + 32 bytes of randoms, then the curve params and key.
	signed := make([]byte, 0, 64+len(params))
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, params...)
	// ECDSA signs a hash, not the message itself. SHA-256 matches the
	// sig_alg we announce below.
	sum := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return nil, err
	}
	sigASN1, err := asn1FromRS(r, s)
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, len(params)+4+len(sigASN1))
	body = append(body, params...)
	body = append(body, 4, 3) // sha256, ecdsa
	body = append(body, byte(len(sigASN1)>>8), byte(len(sigASN1)))
	body = append(body, sigASN1...)
	return encodeHandshake(hsServerKeyExchange, body), nil
}

// asn1FromRS encodes an ECDSA signature (the two numbers r and s) in the DER
// form TLS expects:
//
//	0x30 len                SEQUENCE
//	  0x02 len r-bytes      INTEGER r
//	  0x02 len s-bytes      INTEGER s
//
// DER integers are signed, so if the top bit of the first byte is set we add a
// leading 0x00 to keep the number positive. It only supports the short length
// form (under 128 bytes), which is always enough for P-256.
func asn1FromRS(r, s *big.Int) ([]byte, error) {
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > 0 && rb[0]&0x80 != 0 {
		rb = append([]byte{0}, rb...)
	}
	if len(sb) > 0 && sb[0]&0x80 != 0 {
		sb = append([]byte{0}, sb...)
	}
	inner := make([]byte, 0, 4+len(rb)+len(sb))
	inner = append(inner, 0x02, byte(len(rb)))
	inner = append(inner, rb...)
	inner = append(inner, 0x02, byte(len(sb)))
	inner = append(inner, sb...)
	out := make([]byte, 0, 2+len(inner))
	if len(inner) < 128 {
		out = append(out, 0x30, byte(len(inner)))
	} else {
		return nil, fmt.Errorf("mintls: signature too large")
	}
	out = append(out, inner...)
	return out, nil
}

// decodeClientKeyExchange extracts the client's ephemeral ECDH public key from
// a ClientKeyExchange body (RFC 8422 section 5.7):
//
//	pubkey_len(1) pubkey(pubkey_len)     65 bytes for an uncompressed P-256 point
//
// The caller checks that the bytes are a valid point.
func decodeClientKeyExchange(body []byte) ([]byte, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("mintls: empty ClientKeyExchange")
	}
	n := int(body[0])
	if 1+n > len(body) {
		return nil, fmt.Errorf("mintls: bad ClientKeyExchange")
	}
	return append([]byte{}, body[1:1+n]...), nil
}

// encodeFinished builds a Finished message (RFC 5246 section 7.4.9). Its body
// is only the 12-byte verify_data, with no extra length prefix:
//
//	msg_type(1)=20 length(3)=12 verify_data(12)
func encodeFinished(verify []byte) []byte {
	return encodeHandshake(hsFinished, verify)
}

// SelfSigned creates a fresh ECDSA P-256 key and a self-signed leaf
// certificate for it, valid from one hour ago for one year. The certificate
// is for the given DNS names and, if ip is IPv4, that IP address. Clients will
// not trust it by default (hence curl -k), but it is enough to run the handshake.
func SelfSigned(ip net.IP, dnsNames []string) (certDER []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour), // tolerate a client clock that is a bit behind
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature, // the key signs ServerKeyExchange
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	if ip4 := ip.To4(); ip4 != nil {
		tmpl.IPAddresses = []net.IP{append(net.IP(nil), ip4...)}
	}
	// Template and parent are the same certificate: it signs itself.
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return certDER, key, nil
}
