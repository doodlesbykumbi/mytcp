package mintls

// This file turns one shared secret into all the keys TLS needs. The tool for
// that is the TLS 1.2 PRF (pseudo-random function, RFC 5246 section 5): feed
// it a secret, a text label, and a seed, and it produces as many
// random-looking bytes as you ask for. Different labels give unrelated
// outputs, so one secret can safely produce many different keys.

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Protocol numbers used on the wire.
const (
	// VersionTLS12 is the TLS 1.2 version number as it appears in record
	// headers and ServerHello: major 3, minor 3 (TLS 1.2 is "SSL 3.3").
	VersionTLS12 = 0x0303

	// CipherECDHE_ECDSA_AES128_GCM_SHA256 is the one cipher suite we speak,
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (RFC 5289).
	CipherECDHE_ECDSA_AES128_GCM_SHA256 uint16 = 0xc02b

	// Record content types: the first byte of every record header.
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHandshake        = 22
	recordApplicationData  = 23

	// Handshake message types: the first byte of every handshake message.
	hsClientHello       = 1
	hsServerHello       = 2
	hsCertificate       = 11
	hsServerKeyExchange = 12
	hsServerHelloDone   = 14
	hsClientKeyExchange = 16
	hsFinished          = 20

	// curvesecp256r1 is the TLS ID of the NIST P-256 curve (RFC 8422).
	curvesecp256r1 uint16 = 23
)

// pHash implements P_hash from RFC 5246 section 5. It stretches secret and
// seed into outLen bytes using HMAC:
//
//	A(0) = seed
//	A(i) = HMAC(secret, A(i-1))
//	output = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
//
// Each HMAC call yields one hash length (32 bytes for SHA-256). We keep going
// until we have enough, then cut the output to outLen.
func pHash(h func() hash.Hash, secret, seed []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	a := seed // A(0)
	for len(out) < outLen {
		a = hmacSHA(h, secret, a) // A(i)
		out = append(out, hmacSHA(h, secret, append(a, seed...))...)
	}
	return out[:outLen]
}

// hmacSHA returns HMAC(key, data) using hash h. HMAC is a keyed hash: without
// the key, nobody can compute or predict its output.
func hmacSHA(h func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(h, key)
	m.Write(data)
	return m.Sum(nil)
}

// prf12 is the TLS 1.2 PRF for our suite (RFC 5246 section 5):
//
//	PRF(secret, label, seed) = P_SHA256(secret, label || seed)
//
// The label is an ASCII string such as "master secret" with no trailing zero.
func prf12(secret []byte, label string, seed []byte, outLen int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)
	return pHash(sha256.New, secret, labelSeed, outLen)
}

// masterSecret derives the 48-byte master secret (RFC 5246 section 8.1):
//
//	master_secret = PRF(pre_master_secret, "master secret",
//	                    client_random || server_random)[0..47]
//
// The pre-master secret is the raw ECDH output. Mixing in both randoms makes
// the master secret unique to this connection.
func masterSecret(preMaster, clientRandom, serverRandom []byte) []byte {
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	return prf12(preMaster, "master secret", seed, 48)
}

// keyBlock expands the master secret into the record keys (RFC 5246 section
// 6.3):
//
//	key_block = PRF(master_secret, "key expansion",
//	                server_random || client_random)
//
// Note the seed order: server random first here, the reverse of masterSecret.
// The block is then cut into pieces. AES-GCM needs no separate MAC keys, so
// for this suite the 40 bytes are:
//
//	client_write_key(16)  server_write_key(16)  client_write_IV(4)  server_write_IV(4)
//
// The keys are AES-128 keys. The 4-byte "IVs" are the fixed salt half of the
// GCM nonce (RFC 5288). Each direction has its own key, so the two directions
// never share a key and nonce.
func keyBlock(master, clientRandom, serverRandom []byte) (clientKey, serverKey, clientIV, serverIV []byte) {
	seed := append(append([]byte{}, serverRandom...), clientRandom...)
	block := prf12(master, "key expansion", seed, 40)
	return block[0:16], block[16:32], block[32:36], block[36:40]
}

// finishedVerify computes verify_data for a Finished message (RFC 5246
// section 7.4.9):
//
//	verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..11]
//
// label is "client finished" or "server finished". hsHash is the SHA-256 of
// every handshake message so far. Only someone who knows the master secret can
// compute this, and it changes if any handshake byte was altered on the way.
func finishedVerify(master []byte, label string, hsHash []byte) []byte {
	return prf12(master, label, hsHash, 12)
}
