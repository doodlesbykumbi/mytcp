package mintls

// This file is the record layer: the framing that carries everything else.
// Every TLS record on the wire starts with a 5-byte header (RFC 5246
// section 6.2.1):
//
//	type(1) version(2) length(2) payload(length)
//
// Before ChangeCipherSpec the payload is plaintext. After it, the payload is
// an AES-GCM record (RFC 5246 section 6.2.3.3, RFC 5288):
//
//	explicit_nonce(8) ciphertext(length-24) tag(16)

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// halfConn is the encryption state for one direction of the connection.
// Conn has two: one to decrypt client records, one to encrypt ours.
type halfConn struct {
	// seq counts records sent in this direction, starting at 0 after
	// ChangeCipherSpec. It is never sent as its own field, but both sides
	// track it, and it goes into the nonce and the AAD. A replayed, dropped
	// or reordered record therefore fails to decrypt.
	seq     uint64
	aead    cipher.AEAD // AES-128-GCM
	fixedIV []byte      // 4-byte salt from the key block: the implicit half of the nonce
}

// newGCM sets up AES-128-GCM for one direction with the given 16-byte key and
// 4-byte fixed IV (salt), with the sequence number at 0.
func newGCM(key, fixedIV []byte) (*halfConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// GCM turns AES into an AEAD: it encrypts and also adds a 16-byte tag
	// that detects any change to the ciphertext or the additional data.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 4)
	copy(iv, fixedIV)
	return &halfConn{aead: aead, fixedIV: iv}, nil
}

// nonce builds the 12-byte GCM nonce (RFC 5288 section 3):
//
//	salt(4) from the key block || explicit_nonce(8) from the record
//
// The salt is secret and never sent. The explicit part travels in front of
// each record.
func (h *halfConn) nonce(explicit []byte) []byte {
	n := make([]byte, 12)
	copy(n[:4], h.fixedIV)
	copy(n[4:], explicit)
	return n
}

// seal encrypts one record's plaintext and returns the record payload:
//
//	explicit_nonce(8) ciphertext(len(plaintext)) tag(16)
//
// The additional authenticated data (AAD) is (RFC 5246 section 6.2.3.3):
//
//	seq_num(8) type(1) version(2) length(2)
//
// where length is the plaintext length. The AAD is not encrypted and the
// sequence number is not even sent, but the tag covers them. So an attacker
// cannot relabel a record's type, change its length, or replay it at a
// different position without the tag check failing.
func (h *halfConn) seal(typ byte, vers uint16, plaintext []byte) []byte {
	// We use the sequence number as the explicit nonce. It counts up and
	// never repeats, and a GCM nonce must never repeat under the same key:
	// reusing one leaks the XOR of two plaintexts and lets an attacker
	// forge tags.
	explicit := make([]byte, 8)
	binary.BigEndian.PutUint64(explicit, h.seq)
	nonce := h.nonce(explicit)
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], h.seq)
	aad[8] = typ
	aad[9] = byte(vers >> 8)
	aad[10] = byte(vers)
	binary.BigEndian.PutUint16(aad[11:13], uint16(len(plaintext)))
	// Seal returns ciphertext with the 16-byte tag appended.
	ciphertext := h.aead.Seal(nil, nonce, plaintext, aad)
	h.seq++
	// explicit nonce || ciphertext || tag
	out := make([]byte, 0, 8+len(ciphertext))
	out = append(out, explicit...)
	out = append(out, ciphertext...)
	return out
}

// open is the reverse of seal. It takes the record type and version from
// the header that arrived, rebuilds the same AAD with our own count of the
// peer's sequence number, and checks the tag while decrypting. If anything
// differs from what the sender sealed, it returns an error and no plaintext.
func (h *halfConn) open(typ byte, vers uint16, payload []byte) ([]byte, error) {
	// The smallest valid payload is 8 bytes of explicit nonce plus the
	// 16-byte tag (an empty plaintext).
	if len(payload) < 8+h.aead.Overhead() {
		return nil, fmt.Errorf("mintls: short encrypted record")
	}
	explicit := payload[:8]
	ciphertext := payload[8:] // still has the tag at the end
	nonce := h.nonce(explicit)
	// The AAD length field is the plaintext length, as the sender saw it.
	plainLen := len(ciphertext) - h.aead.Overhead()
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], h.seq)
	aad[8] = typ
	aad[9] = byte(vers >> 8)
	aad[10] = byte(vers)
	binary.BigEndian.PutUint16(aad[11:13], uint16(plainLen))
	plain, err := h.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("mintls: gcm open: %w", err)
	}
	// Only count records that authenticated.
	h.seq++
	return plain, nil
}

// readRecord reads exactly one record from r: the 5-byte header, then the
// payload whose length the header announces. TCP is a byte stream with no
// message boundaries, so this header is how we find where a record ends.
func readRecord(r io.Reader) (typ byte, vers uint16, payload []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, 0, nil, err
	}
	typ = hdr[0]
	vers = binary.BigEndian.Uint16(hdr[1:3])
	n := binary.BigEndian.Uint16(hdr[3:5])
	// Plaintext is at most 2^14 = 16384 bytes. We allow a little extra for
	// the encryption overhead, and refuse anything larger.
	if n > 16384+256 {
		return 0, 0, nil, fmt.Errorf("mintls: record too large: %d", n)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	return typ, vers, payload, nil
}

// writeRecord writes one record: the 5-byte header followed by payload.
// payload is already encrypted if keys are active; this function only frames.
func writeRecord(w io.Writer, typ byte, vers uint16, payload []byte) error {
	if len(payload) > 16384 {
		return fmt.Errorf("mintls: payload too large")
	}
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint16(hdr[1:3], vers)
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
