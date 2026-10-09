#!/usr/bin/env bash
# mytcp as an internet client: Go's http.Client, dialing over our TCP,
# out through tap0 → the container's NAT → the real internet. The name is
# looked up by our own DNS client over our own UDP, so strace must show no
# AF_INET socket at all. Needs outbound network.
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/mytcp ./cmd/mytcp
bash scripts/lab-nat.sh

ip link del tap0 2>/dev/null || true
ip tuntap add dev tap0 mode tap
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up
trap 'ip link del tap0 2>/dev/null || true' EXIT

url="${1:-https://www.google.com/}"
timeout 30 strace -f -qq -e trace=%network -o /tmp/mytcp.strace \
  /tmp/mytcp -i tap0 -get "$url" -dump=false -pcap captures/latest >/tmp/mytcp.body 2>/tmp/mytcp.log
grep -qi '<html' /tmp/mytcp.body
grep -E '^HTTP/' /tmp/mytcp.log
grep -E 'dns: .* is ' /tmp/mytcp.log

# The `ip` commands that configure tap0 use netlink sockets; those are
# setup, not traffic. Anything AF_INET would be the kernel's TCP or UDP.
if grep -E 'socket\(AF_INET6?,|connect\(' /tmp/mytcp.strace; then
  echo "mytcp made kernel socket calls (see /tmp/mytcp.strace)" >&2
  exit 1
fi
echo "network syscalls traced: $(wc -l </tmp/mytcp.strace) (all netlink setup)"
echo "internet smoke ok ($url), no kernel sockets"
