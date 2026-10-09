//go:build linux

// Package tap is the bottom of the stack: a Linux TAP device, which is a
// virtual Ethernet cable between the kernel and this process.
//
// Everything the kernel sends out of the TAP interface arrives here as one
// raw Ethernet frame per Read, and every Write injects one frame as if it
// had come in over a wire. The layer above is package eth. There is no
// layer below: this is where bytes leave Go and enter the kernel.
//
// Deliberately left out: TUN mode (raw IP without Ethernet headers),
// multi-queue devices, and non-Linux platforms (see tap_stub.go).
package tap

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Constants from the Linux header <linux/if_tun.h>. Go has no binding for
// them, so the raw values are copied here.
const (
	// iffTap asks for a TAP device (Ethernet frames) rather than TUN (IP packets).
	iffTap = 0x0002
	// iffNoPI turns off the 4-byte "packet information" prefix the kernel
	// would otherwise put in front of every frame, so reads start directly
	// at the Ethernet header.
	iffNoPI = 0x1000
	// tunSetIff is the TUNSETIFF ioctl request number: "turn this open
	// /dev/net/tun file into the interface described by this ifreq".
	tunSetIff = 0x400454ca
)

// ifreq mirrors the kernel's struct ifreq, which is 40 bytes on 64-bit
// Linux: a 16-byte interface name followed by a 24-byte union. TUNSETIFF
// only reads the flags field at the start of that union; the rest is padding.
type ifreq struct {
	name  [16]byte // NUL-terminated interface name, e.g. "tap0"
	flags uint16   // IFF_* flags
	_     [22]byte // rest of the union, unused
}

// Device is an open TAP interface (Ethernet frames, no packet info header).
type Device struct {
	f    *os.File
	fd   int    // raw file descriptor, used directly for blocking reads and writes
	name string // interface name the kernel actually assigned
}

// Open creates or attaches to a TAP device. name may be empty (kernel picks)
// or e.g. "tap0". Requires CAP_NET_ADMIN.
//
// It opens the clone device /dev/net/tun and then uses the TUNSETIFF ioctl
// to bind that file to a TAP interface. From then on, the file descriptor
// reads and writes whole Ethernet frames.
func Open(name string) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	fd := int(f.Fd())
	// Keep the fd in blocking mode and bypass Go's netpoller: Read and Write
	// below call unix.Read/unix.Write on the raw fd, and each call blocks its
	// goroutine until a frame is available or sent. Going through
	// os.File.Read instead can fail with "not pollable" on this device.
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("set blocking: %w", err)
	}

	var req ifreq
	req.flags = iffTap | iffNoPI
	// An empty name leaves the field all zeros, which asks the kernel to
	// pick the next free name (tap0, tap1, ...).
	if name != "" {
		copy(req.name[:], name)
	}

	// ioctl(fd, TUNSETIFF, &req). The kernel reads the name and flags, creates
	// or attaches to the interface, and writes the final name back into req.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = f.Close()
		// EBUSY on a named device usually means an earlier run still holds it.
		if errno == syscall.EBUSY && name != "" {
			return nil, fmt.Errorf("TUNSETIFF %s: busy — another process already owns this TAP (pkill mytcp?)", name)
		}
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	return &Device{f: f, fd: fd, name: cString(req.name[:])}, nil
}

// cString converts a NUL-terminated C string in a fixed-size buffer into a
// Go string, stopping at the first zero byte.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Name returns the interface name, e.g. "tap0".
func (d *Device) Name() string { return d.name }

// Read blocks until the kernel sends a frame out of the TAP interface, then
// copies exactly one Ethernet frame into p. p should be at least as large as
// the interface MTU plus the 14-byte Ethernet header.
func (d *Device) Read(p []byte) (int, error) {
	n, err := unix.Read(d.fd, p)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Write injects p into the kernel as one Ethernet frame received on the TAP
// interface. p must be a complete frame, starting at the Ethernet header.
func (d *Device) Write(p []byte) (int, error) {
	n, err := unix.Write(d.fd, p)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Close closes the file descriptor. Unless the interface was made
// persistent by other tools, the kernel removes it.
func (d *Device) Close() error { return d.f.Close() }
