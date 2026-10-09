#!/usr/bin/env bash
# Live TAP smoke test — run inside Linux (e.g. Docker lab with NET_ADMIN).
#
# Brings up tap0 (kernel = 10.0.0.1), starts mytcp as 10.0.0.2 for each
# -app mode, and checks with ordinary host tools (ping / curl / nc). Then
# flips it round: mytcp dials out to nc listeners on the kernel side.
# Invoked via: make smoke  or  ./scripts/lab.sh smoke
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/mytcp ./cmd/mytcp

# Fresh TAP each run so a leftover interface cannot poison the test.
ip link del tap0 2>/dev/null || true
ip tuntap add dev tap0 mode tap
if [[ -w /proc/sys/net/ipv6/conf/tap0/disable_ipv6 ]]; then
  echo 1 > /proc/sys/net/ipv6/conf/tap0/disable_ipv6
fi
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up

# Always tear down the stack process and TAP on exit (success or failure).
# --- HTTP (default app) ---
/tmp/mytcp -i tap0 -app http -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true; ip link del tap0 2>/dev/null || true' EXIT
sleep 0.4

ping -c 3 -W 1 10.0.0.2
curl -fsS --max-time 2 http://10.0.0.2/ | grep -q mytcp
echo "http smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTP via Go's net/http.Server on the same Listener ---
/tmp/mytcp -i tap0 -app http-go -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.4
curl -fsS --max-time 2 http://10.0.0.2/ | grep -q mytcp
echo "http-go smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTPS stdlib (crypto/tls) ---
/tmp/mytcp -i tap0 -app https -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.5
curl -kfsS --max-time 5 https://10.0.0.2/ | grep -q mytcp
echo "https smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTPS all stdlib (tls.NewListener + net/http.Server on our Listener) ---
/tmp/mytcp -i tap0 -app https-go -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.5
curl -kfsS --max-time 5 https://10.0.0.2/ | grep -q mytcp
echo "https-go smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTPS DIY (mintls TLS 1.2 only; curl pinned to 1.2) ---
/tmp/mytcp -i tap0 -app https-diy -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.5
curl -kfsS --tlsv1.2 --tls-max 1.2 --max-time 5 https://10.0.0.2/ | grep -q mytcp
echo "https-diy smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- Echo on TCP port 7 ---
/tmp/mytcp -i tap0 -app echo -tcp 7 -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.4
printf 'hello-from-smoke\n' | nc -q1 -w2 10.0.0.2 7 | grep -q hello-from-smoke
echo "echo smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- Client: raw dial to nc on the kernel side, bytes both ways ---
# nc must keep reading until our bytes arrive, so its stdin stays open a
# second; with stdin already at EOF it closes at once and resets them.
(printf 'hello-from-kernel\n'; sleep 1) | nc -l -q0 9000 >/tmp/nc.out &
ncpid=$!
sleep 0.2
printf 'hello-from-mytcp\n' \
  | timeout 10 /tmp/mytcp -i tap0 -dial 10.0.0.1:9000 -dump=false -pcap '' 2>/tmp/mytcp.log \
  | grep -q hello-from-kernel
wait $ncpid 2>/dev/null || true
grep -q hello-from-mytcp /tmp/nc.out
echo "dial smoke ok"

# --- Client: nobody listening on the kernel side, so its RST refuses us ---
if timeout 10 /tmp/mytcp -i tap0 -dial 10.0.0.1:9 -dump=false -pcap '' </dev/null 2>/tmp/mytcp.log; then
  echo "dial to a closed port succeeded" >&2; exit 1
fi
grep -q 'connection refused' /tmp/mytcp.log
echo "dial refused smoke ok"

# --- Client: Go's http.Client over our Dial, against a canned response ---
(printf 'HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\nhello-from-nc!\n'; sleep 1) | nc -l -q0 8080 >/tmp/nc.out &
ncpid=$!
sleep 0.2
timeout 15 /tmp/mytcp -i tap0 -get http://10.0.0.1:8080/ -dump=false -pcap '' 2>/tmp/mytcp.log \
  | grep -q hello-from-nc
wait $ncpid 2>/dev/null || true
grep -q 'GET / HTTP/1.1' /tmp/nc.out
echo "get smoke ok"
echo "smoke ok"
