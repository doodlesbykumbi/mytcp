// Package capture records frames to disk for later inspection (JSONL + PCAP).
//
// It sits beside the stack, at the TAP boundary: every raw Ethernet frame
// read from or written to the TAP device can be handed to a Recorder. Each
// frame goes to two files: a JSON Lines file for the browser UI, and a
// classic PCAP file that Wireshark or tcpdump can open. It does not decode
// frames; it stores the bytes exactly as they crossed the TAP device.
package capture

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Dir is RX or TX from our process's point of view.
type Dir string

const (
	// RX marks a frame received from the TAP device (sent by the kernel).
	RX Dir = "RX"
	// TX marks a frame this stack wrote to the TAP device.
	TX Dir = "TX"
)

// Recorder writes a .jsonl (for the browser UI) and a .pcap (Wireshark).
// It is safe for concurrent use: the receive loop and senders can share one.
type Recorder struct {
	mu   sync.Mutex // serializes writes so records from different goroutines never interleave
	json *os.File
	pcap *os.File
	n    int    // sequence number of the next record, starting at 0
	base string // path without extension; both files are base + suffix
}

// record is one line of the .jsonl file, for example:
//
//	{"n":0,"t_us":1759190400000000,"dir":"RX","data":"ffffffffffff..."}
type record struct {
	N    int    `json:"n"`
	TUs  int64  `json:"t_us"` // wall-clock time in microseconds since the Unix epoch
	Dir  string `json:"dir"`
	Data string `json:"data"` // hex, no spaces
}

// Open creates captures/<name>.jsonl and captures/<name>.pcap (dirs created).
// name is a path stem, e.g. "captures/run" or "captures/run.jsonl" (suffix stripped).
// Existing files with those names are truncated.
func Open(path string) (*Recorder, error) {
	base := path
	switch filepath.Ext(base) {
	case ".jsonl", ".pcap":
		base = base[:len(base)-len(filepath.Ext(base))]
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil && filepath.Dir(base) != "." {
		return nil, err
	}

	jf, err := os.Create(base + ".jsonl")
	if err != nil {
		return nil, err
	}
	pf, err := os.Create(base + ".pcap")
	if err != nil {
		_ = jf.Close()
		return nil, err
	}
	r := &Recorder{json: jf, pcap: pf, base: base}
	if err := r.writePCAPHeader(); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

// Path returns the path stem shared by the two files, without extension.
func (r *Recorder) Path() string { return r.base }

// writePCAPHeader writes the 24-byte global header that starts every
// classic PCAP file:
//
//	0       4     6     8        12        16        20        24
//	+-------+-----+-----+--------+---------+---------+---------+
//	| magic |major|minor|thiszone| sigfigs | snaplen | linktype|
//	+-------+-----+-----+--------+---------+---------+---------+
//
// Unlike the network protocols, PCAP fields are in the writer's byte
// order. This file is always little-endian; readers detect that from the
// magic number, which reads as d4 c3 b2 a1 on disk.
func (r *Recorder) writePCAPHeader() error {
	// Classic PCAP, little-endian, LINKTYPE_ETHERNET = 1
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // bytes 0-3: magic, also means "timestamps are in microseconds"
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // bytes 4-5: format version 2.4, major part
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // bytes 6-7: minor part
	// Bytes 8-15 stay zero: timezone offset and timestamp accuracy, both unused.
	binary.LittleEndian.PutUint32(hdr[16:20], 65535) // bytes 16-19: snaplen, the largest frame a reader should expect
	binary.LittleEndian.PutUint32(hdr[20:24], 1)     // bytes 20-23: link type 1 = Ethernet, so Wireshark decodes from the MAC header
	_, err := r.pcap.Write(hdr)
	return err
}

// Write appends one Ethernet frame.
// The frame is written to both files, each is synced to disk right away so
// a crash or Ctrl-C loses nothing, and both get the same timestamp.
func (r *Recorder) Write(dir Dir, frame []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	rec := record{
		N:    r.n,
		TUs:  now.UnixMicro(),
		Dir:  string(dir),
		Data: hex.EncodeToString(frame),
	}
	r.n++

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := r.json.Write(append(line, '\n')); err != nil {
		return err
	}
	_ = r.json.Sync()

	// Every packet in a PCAP file starts with a 16-byte record header,
	// little-endian like the global header:
	//
	//	0        4         8          12         16
	//	+--------+---------+----------+----------+-----------
	//	| ts sec | ts usec | incl_len | orig_len | frame bytes...
	//	+--------+---------+----------+----------+-----------
	//
	// PCAP has no direction field, so RX/TX is only recorded in the .jsonl.
	ph := make([]byte, 16)
	binary.LittleEndian.PutUint32(ph[0:4], uint32(now.Unix()))            // bytes 0-3: timestamp, whole seconds
	binary.LittleEndian.PutUint32(ph[4:8], uint32(now.Nanosecond()/1000)) // bytes 4-7: microseconds within that second
	// The whole frame is always saved, so the captured length equals the original length.
	binary.LittleEndian.PutUint32(ph[8:12], uint32(len(frame)))  // bytes 8-11: bytes saved in this file
	binary.LittleEndian.PutUint32(ph[12:16], uint32(len(frame))) // bytes 12-15: bytes originally on the wire
	if _, err := r.pcap.Write(ph); err != nil {
		return err
	}
	if _, err := r.pcap.Write(frame); err != nil {
		return err
	}
	return r.pcap.Sync()
}

// Close closes both files and returns the first error it hit. Calling it
// again is harmless, but Write must not be called after Close.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	if r.json != nil {
		err = r.json.Close()
		r.json = nil
	}
	if r.pcap != nil {
		if e := r.pcap.Close(); e != nil && err == nil {
			err = e
		}
		r.pcap = nil
	}
	return err
}

// String describes where the recorder writes, for startup logs.
func (r *Recorder) String() string {
	return fmt.Sprintf("%s.jsonl + %s.pcap", r.base, r.base)
}
