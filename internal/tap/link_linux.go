//go:build linux

package tap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ConfigureHostSide brings iface up and assigns the kernel-side address
// (the peer of our userspace stack). Uses the `ip` tool from iproute2.
// Best-effort: disable IPv6 on the iface (often blocked inside Docker —
// see docker-compose sysctls for the reliable path).
//
// The TAP interface has two ends. The kernel end gets cidr (for example
// "10.0.0.1/24") so the kernel knows to route that subnet through the TAP;
// this process plays a different IP on the same subnet. Disabling IPv6
// keeps the kernel from sending IPv6 neighbor discovery and multicast
// frames that this IPv4-only stack would have to ignore.
func ConfigureHostSide(iface, cidr string) error {
	if err := disableIPv6(iface); err != nil {
		// Non-fatal: compose sysctls usually cover this in the lab.
		fmt.Fprintf(os.Stderr, "tap: disable IPv6 on %s: %v (IPv6 ND/MLD may still appear)\n", iface, err)
	}

	// Equivalent to running: ip link set dev <iface> up
	if out, err := exec.Command("ip", "link", "set", "dev", iface, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up: %w (%s)", iface, err, out)
	}
	// No address requested: leave the interface up but unaddressed.
	if cidr == "" {
		return nil
	}
	// "replace" rather than "add", so running twice does not fail with
	// "address already assigned".
	if out, err := exec.Command("ip", "addr", "replace", cidr, "dev", iface).CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr replace %s dev %s: %w (%s)", cidr, iface, err, out)
	}
	return nil
}

// disableIPv6 turns off IPv6 on iface by writing "1" to the kernel setting
// /proc/sys/net/ipv6/conf/<iface>/disable_ipv6. If the setting is already 1,
// it does not write. Inside a container /proc/sys is often read-only, so the
// write can fail.
func disableIPv6(iface string) error {
	path := filepath.Join("/proc/sys/net/ipv6/conf", iface, "disable_ipv6")
	if cur, err := os.ReadFile(path); err == nil {
		if len(cur) > 0 && cur[0] == '1' {
			return nil // already off (e.g. compose sysctls)
		}
	}
	if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
		return err
	}
	return nil
}
