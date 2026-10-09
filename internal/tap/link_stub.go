//go:build !linux

package tap

import "fmt"

// ConfigureHostSide is the non-Linux placeholder for the Linux version,
// which configures the kernel side of the TAP interface. It always fails.
func ConfigureHostSide(iface, cidr string) error {
	return fmt.Errorf("ConfigureHostSide is Linux-only")
}
