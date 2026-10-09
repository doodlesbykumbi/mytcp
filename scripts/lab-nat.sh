#!/usr/bin/env bash
# Lets mytcp (10.0.0.2 on tap0) reach the internet through the lab
# container. The kernel side of tap0 (10.0.0.1) is mytcp's gateway; the
# kernel forwards its packets out of the default interface and rewrites
# the source to the container's own address (MASQUERADE), so replies
# find their way back. Safe to run more than once.
set -euo pipefail

if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || {
    echo "ip_forward is off and cannot be set here; recreate the lab (make lab-down lab-up)" >&2
    exit 1
  }
fi

out=$(ip route show default | awk '{print $5; exit}')
rule=(POSTROUTING -s 10.0.0.0/24 -o "$out" -j MASQUERADE)
iptables -t nat -C "${rule[@]}" 2>/dev/null || iptables -t nat -A "${rule[@]}"
echo "NAT on: 10.0.0.0/24 → $out"
