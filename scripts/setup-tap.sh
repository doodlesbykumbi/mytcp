#!/usr/bin/env bash
# Create/configure a TAP for the mytcp userspace stack.
#
# Topology (IPv4 /24):
#   host/kernel side  → 10.0.0.1  (this script)
#   mytcp stack       → 10.0.0.2  (claimed when you run /tmp/mytcp -i tap0)
#
# Usage (inside the lab container, usually as root / with NET_ADMIN):
#   scripts/setup-tap.sh [iface] [host_cidr]
#   scripts/setup-tap.sh              # tap0 + 10.0.0.1/24
set -euo pipefail

IFACE="${1:-tap0}"
HOST_IP="${2:-10.0.0.1/24}"

# Create the TAP device if it does not already exist.
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  ip tuntap add dev "$IFACE" mode tap
fi

# Quiet IPv6 ND/RS noise on this learning TAP (stack is IPv4-only).
if [[ -w "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6" ]]; then
  echo 1 > "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6"
fi

# Assign the kernel's address and bring the link up.
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "$HOST_IP" dev "$IFACE"
ip link set "$IFACE" up

echo "ok: $IFACE up with $HOST_IP (stack should claim the .2 on that /24)"
