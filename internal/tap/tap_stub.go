//go:build !linux

package tap

import (
	"fmt"
	"runtime"
)

// Device is a placeholder on non-Linux hosts (macOS has no stock TAP).
// It exists so the rest of the stack, and its tests, still compile on a
// laptop; every I/O method just fails.
type Device struct{}

// Open explains how to run under Linux/Docker.
// It always returns an error naming the current OS and architecture.
func Open(name string) (*Device, error) {
	return nil, fmt.Errorf("TAP is Linux-only (this host is %s/%s); run under Docker — see README", runtime.GOOS, runtime.GOARCH)
}

// Name, Read, Write and Close mirror the Linux Device API. There is no
// interface behind them, so Read and Write always fail with errStub.
func (d *Device) Name() string                { return "" }
func (d *Device) Read(p []byte) (int, error)  { return 0, errStub }
func (d *Device) Write(p []byte) (int, error) { return 0, errStub }
func (d *Device) Close() error                { return nil } // nothing was opened, so nothing to close

// errStub is the error every stub I/O method returns.
var errStub = fmt.Errorf("TAP not available on this platform")
