# mytcp

Userspace Ethernet → IPv4 → ICMP/TCP stack in Go, driven by a Linux **TAP**
device. You own the packet bytes; the kernel only shuttles frames.

**Talk (no install):** [doodlesbykumbi.github.io/mytcp/talk/](https://doodlesbykumbi.github.io/mytcp/talk/)

See [ARCHITECTURE.md](ARCHITECTURE.md) for bottom↔top walkthroughs,
[IMPLEMENTATION.md](IMPLEMENTATION.md) for an honest feature matrix
(including what “windowing” does and does not mean here),
[ROADMAP.md](ROADMAP.md) for the stage-by-stage story,
and [docs/talk](docs/talk/) for the Reveal talk deck (`make talk` locally).

## Why TAP (not TUN)

| | TUN | TAP |
|---|---|---|
| Bytes on the fd | IP packets | Ethernet frames |
| You implement | IP and up | Ethernet + ARP, then IP and up |

This project uses TAP so Stage 0 starts at the lowest userspace frame layout.

### Why not native macOS?

macOS has no stock TAP — only L3 `utun` (IP packets, no Ethernet/ARP on the
fd). Third-party TAP kexts are deprecated, and `feth`-based workarounds need
BPF + AF_NDRV plumbing that is not a single TAP-like fd. We stay in the
Linux Docker lab so the I/O stays one clean `read`/`write` of Ethernet
frames and the learning time goes into the stack, not host quirks.

## Lab container (recommended)

One persistent container with Go, `ip`, `ping`, `nc`, and `tcpdump` already
installed. Source is bind-mounted at `/work`.

```bash
cd mytcp
make lab-up       # build image + start mytcp-lab (stays up)
make shell        # bash inside the lab
```

First shell — build and run (configures `tap0` + `10.0.0.1/24` for you):

```bash
make lab-build                # from the Mac, or: go build -o /tmp/mytcp ./cmd/mytcp
/tmp/mytcp -i tap0 -app http -dump=false
# or from the Mac:  make lab-run
```

You should see `HTTP/1 (our server on net.Listener) :80`. Then in another shell:

```bash
make shell
curl http://10.0.0.2/
# http-go:  /tmp/mytcp -i tap0 -app http-go -dump=false   # Go’s net/http.Server
# https:    /tmp/mytcp -i tap0 -app https -dump=false
#           curl -k https://10.0.0.2/
# https-go: /tmp/mytcp -i tap0 -app https-go -dump=false  # tls.NewListener + net/http.Server
# https-diy:/tmp/mytcp -i tap0 -app https-diy -dump=false
#           curl -k --tlsv1.2 --tls-max 1.2 https://10.0.0.2/
# echo mode:  /tmp/mytcp -i tap0 -app echo -tcp 7
#             nc 10.0.0.2 7
```

### Client mode (mytcp connects out)

mytcp can also start connections: `-dial` is nc over our TCP, `-get` is
Go's own `http.Client` with our `DialContext` in its Transport. It exits
when the exchange ends.

```bash
# shell 1, kernel side of the cable:
nc -l 9000
# shell 2:
/tmp/mytcp -i tap0 -dial 10.0.0.1:9000 -dump=false     # type; lines go both ways

# out to the internet, via the kernel as gateway + NAT:
make lab-nat                                          # once per lab start
/tmp/mytcp -i tap0 -get http://example.com/ -dump=false
make smoke-internet                                   # the same, as a check
```

Names are resolved by our own DNS client over our own UDP (`-dns`, default
`1.1.1.1`), so the client path opens no kernel sockets. To see it:

```bash
strace -f -e trace=%network /tmp/mytcp -i tap0 -get https://www.google.com/ -dump=false
# only netlink, from the `ip` commands that set up tap0; no AF_INET
```

### Packet inspector (browser)

Captures write `captures/<name>.jsonl` (for the UI) and `.pcap` (Wireshark).

```bash
# lab (default -pcap captures/latest):
/tmp/mytcp -i tap0 -app http -dump=false -pcap captures/latest
curl http://10.0.0.2/

# Mac:
make ui                 # http://127.0.0.1:8765
make ui UI_PORT=9000    # if 8765 is taken
```

The UI lists packets, peels L2→L7 (including HTTP), and highlights hex ranges when you click a layer.
Other helpers:

```bash
make smoke        # every server app, then -dial / -get against nc
make status
make lab-down     # stop when you're done for the day
make help         # all targets
```

Compose details: [`docker-compose.yml`](docker-compose.yml) (`NET_ADMIN` + `/dev/net/tun`).
Image: [`Dockerfile`](Dockerfile).

### Stage 0 only (hex dump, no replies)

```bash
scripts/setup-tap.sh
go build -o /tmp/mytcp ./cmd/mytcp
/tmp/mytcp -i tap0 -dump-only
# other shell: ping 10.0.0.2   # you'll see ARP frames
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-i` | `tap0` | TAP name |
| `-ip` | `10.0.0.2` | Address we claim |
| `-host` | `10.0.0.1/24` | Kernel-side addr on TAP (`""` skips) |
| `-mac` | `02:00:00:00:00:02` | MAC we claim |
| `-tcp` | `0` → 80/443/7 | Listen port (`http`/`http-go`→80, `https*`→443, `echo`→7) |
| `-app` | `http` | `http`, `http-go`, `https`, `https-go`, `https-diy`, or `echo` |
| `-dump` | `true` | Layered onion decode + hex per header |
| `-dump-only` | `false` | No protocol replies |
| `-pcap` | `captures/latest` | Capture stem (`.jsonl` + `.pcap`); `""` off |
| `-gw` | the `-host` address | Next hop for anything off the `-host` subnet |
| `-dial` | | Client: connect to `host:port`, copy stdin/stdout (no server app) |
| `-get` | | Client: fetch a URL with `net/http.Client` over our TCP |
| `-dns` | `1.1.1.1` | DNS server our resolver asks for `-dial`/`-get` names |

## Layout

```text
cmd/mytcp/          CLI
internal/tap/       Linux TAP open (stub elsewhere)
internal/eth/       Ethernet II
internal/arp/       ARP request/reply
internal/ip4/       IPv4 + checksum
internal/icmp/      Echo request/reply
internal/tcp/       Segments + conn state + Listen/Dial + net.Conn + retransmit
internal/udp/       UDP datagrams (for DNS)
internal/dns/       DNS query/answer wire format (stub resolver lives in stack)
internal/http1/     Tiny HTTP/1 server (Serve on Listener; also Handler for net/http)
internal/https1/    HTTPS: crypto/tls or mintls + http1
internal/mintls/    Minimal TLS 1.2 server (one cipher suite)
internal/stack/     Demux L2→L4, ARP cache, UDP ports, DialContext + DNS lookup
internal/dump/      Layered frame decode (onion)
internal/capture/   JSONL + PCAP writer
web/                Browser packet inspector
captures/           Capture output (gitignored)
Dockerfile          Lab image (Go + net tools)
docker-compose.yml  Long-lived mytcp-lab
Makefile            test / build / lab-up / shell / smoke
ARCHITECTURE.md     Bottom↔top design + mermaid
IMPLEMENTATION.md   Feature matrix — what is / isn’t real
ROADMAP.md          Stage-by-stage growth
scripts/lab.sh      (used by Makefile)
scripts/setup-tap.sh
```

## Tests

Decode/checksum tests run on macOS (no TAP required):

```bash
make test
```
