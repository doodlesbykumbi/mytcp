# mytcp architecture

How the userspace stack fits together — **bottom → top** (bytes upward) and
**top → bottom** (a ping / TCP echo downward).

**What is actually built (windows, retransmit, gaps):** see
[IMPLEMENTATION.md](IMPLEMENTATION.md) — start there if you are asking
“how much TCP is real?”.

Companion: [ROADMAP.md](ROADMAP.md) (growth stages), [README.md](README.md) (run).

---

## Big picture

On a normal machine, `ping` and `nc` talk to the **kernel** TCP/IP stack.
Here the kernel only owns one side of a virtual NIC (`tap0`). The other side
is a file descriptor our Go process reads and writes. **We** implement
Ethernet, ARP, IPv4, ICMP, and a minimal TCP.

```mermaid
flowchart LR
  subgraph host [Linux netns / lab container]
    Apps["ping / nc"]
    KStack["Kernel IP stack"]
    TapDev["tap0 iface<br/>10.0.0.1/24"]
    Apps --> KStack --> TapDev
  end

  subgraph user [mytcp process]
    Fd["TAP fd<br/>unix.Read / Write"]
    Stack["internal/stack<br/>demux L2→L4"]
    Fd --> Stack
    Stack --> Fd
  end

  TapDev -->|"Ethernet frames"| Fd
  Fd -->|"Ethernet frames"| TapDev
```

Defaults: kernel side `10.0.0.1/24`, userspace claims `10.0.0.2` /
`02:00:00:00:00:02`, TCP echo on port `7`.

---

## Package map

```mermaid
flowchart TB
  main["cmd/mytcp"]
  stack["internal/stack"]
  tap["internal/tap"]
  eth["internal/eth"]
  arp["internal/arp"]
  ip4["internal/ip4"]
  icmp["internal/icmp"]
  tcp["internal/tcp"]
  hex["internal/hexdump"]

  main --> tap
  main --> stack
  stack --> eth
  stack --> arp
  stack --> ip4
  stack --> icmp
  stack --> tcp
  stack --> hex
  tcp -->|"Emitter.SendTCP"| stack
```

| Package | Layer | Job |
|---------|-------|-----|
| `tap` | I/O | Open `/dev/net/tun` (`IFF_TAP\|IFF_NO_PI`), blocking read/write, bring link up + host CIDR |
| `eth` | L2 | Ethernet II header decode/encode |
| `arp` | L2.5 | Who-has / is-at for IPv4 over Ethernet |
| `ip4` | L3 | IPv4 header + Internet checksum |
| `icmp` | L3 | Echo request → echo reply |
| `tcp` | L4 | Segments, conn table, handshake, echo, retransmit |
| `stack` | glue | RX demux, TX encapsulate, owns our MAC/IP |
| `hexdump` | debug | Frame dumps when `-dump` |

---

## Bottom → top (what a frame becomes)

Start at the wire-shaped bytes on the TAP fd and climb the layers.

### L2 — Ethernet frame on the TAP

`IFF_NO_PI` means no kernel “packet info” prefix. Each `read` is:

```text
[dst MAC 6][src MAC 6][EtherType 2][payload …]
```

| EtherType | Next |
|-----------|------|
| `0x0806` | ARP |
| `0x0800` | IPv4 |

`stack.HandleFrame` decodes with `eth.Decode`, drops frames not for our MAC
(unless broadcast), then switches on type.

### L2.5 — ARP

Host asks “who-has `10.0.0.2`?” We reply “`02:00:00:00:00:02` is-at”.
Without this, the kernel never sends IPv4 to our MAC.

### L3 — IPv4

Header (20 bytes min): version/IHL, total length, TTL, protocol, src, dst,
checksum. Protocol `1` → ICMP, `6` → TCP. Dest must equal our IP or we ignore.

### L3/L4 — ICMP echo

Type 8 request → type 0 reply, same id/seq/payload. That is `ping`.

### L4 — TCP

Segment: ports, seq, ack, flags, window, checksum (pseudo-header + segment),
payload. `tcp.Stack` keys connections by `(remoteIP, remotePort, localPort)`.

```mermaid
flowchart TB
  bytes["TAP read: raw bytes"]
  ethN["eth.Decode"]
  demux{"EtherType?"}
  arpN["arp — maybe reply"]
  ipN["ip4.Decode"]
  proto{"Proto?"}
  icmpN["icmp echo → reply"]
  tcpN["tcp.Handle"]
  tx["writeFrame → TAP"]

  bytes --> ethN --> demux
  demux -->|0x0806| arpN --> tx
  demux -->|0x0800| ipN --> proto
  proto -->|1 ICMP| icmpN --> tx
  proto -->|6 TCP| tcpN --> tx
```

---

## Top → bottom (how replies are built)

Outbound path is the reverse: application intent → headers wrapped outward →
bytes on the fd.

### ICMP reply path

1. `icmp.ReplyFrom` builds type-0 message + checksum  
2. `stack.sendIPv4` wraps IPv4 (src=us, dst=peer, proto=ICMP)  
3. Ethernet (dst=peer MAC from RX, src=our MAC, type=IPv4)  
4. `nif.Write`

### TCP send path

TCP never talks to TAP directly. It calls `Emitter.SendTCP` (implemented by
`stack.Stack`):

1. `tcp.Segment.Encode` — TCP header + payload + checksum  
2. `sendIPv4` — IP header  
3. `eth.Frame` — L2  
4. `writeFrame`

```mermaid
flowchart TB
  intent["TCP / ICMP decision"]
  seg["TCP segment bytes<br/>or ICMP message"]
  ip["IPv4 datagram"]
  frame["Ethernet frame"]
  fd["TAP write"]

  intent --> seg --> ip --> frame --> fd
```

---

## End-to-end: `ping 10.0.0.2`

```mermaid
sequenceDiagram
  participant Ping as ping
  participant K as Kernel
  participant Tap as tap0
  participant S as mytcp stack

  Ping->>K: ICMP echo to 10.0.0.2
  K->>Tap: ARP who-has 10.0.0.2
  Tap->>S: Ethernet ARP request
  S->>Tap: ARP reply (our MAC)
  Tap->>K: learn 10.0.0.2 → MAC
  K->>Tap: Ethernet + IPv4 + ICMP echo
  Tap->>S: frame
  S->>Tap: Ethernet + IPv4 + ICMP reply
  Tap->>K: deliver
  K->>Ping: echo reply
```

---

## End-to-end: `nc 10.0.0.2 7` (echo)

Minimal TCP we implement: passive open, one data path (echo), passive close,
retransmit of unacked segments.

```mermaid
stateDiagram-v2
  [*] --> Listen: Listen(:7)
  Listen --> SynReceived: SYN
  SynReceived --> Established: ACK of SYN-ACK
  Established --> CloseWait: FIN
  CloseWait --> LastAck: our FIN+ACK
  LastAck --> Closed: final ACK
  Closed --> [*]
```

```mermaid
sequenceDiagram
  participant NC as nc
  participant K as Kernel TCP
  participant S as mytcp tcp.Stack

  NC->>K: connect
  K->>S: SYN
  S->>K: SYN-ACK
  K->>S: ACK
  Note over S: ESTABLISHED
  NC->>K: "hello\\n"
  K->>S: PSH+ACK + payload
  S->>K: PSH+ACK + same payload
  NC->>K: close
  K->>S: FIN
  S->>K: ACK then FIN
  K->>S: ACK
```

**Reliability (Stage 5):** segments that consume seq space are queued as
outstanding. A 100ms tick retransmits after RTO (500ms), up to 5 tries.
Pure ACKs are not queued.

---

## Process loop (`cmd/mytcp`)

```mermaid
flowchart LR
  open["tap.Open + ConfigureHostSide"]
  newS["stack.New + Listen"]
  loop["goroutine: Read → HandleFrame"]
  tick["ticker 100ms → Tick"]
  open --> newS --> loop
  newS --> tick
```

Why not `os.File.Read`? Go’s netpoller cannot epoll `/dev/net/tun` →
`not pollable`. We use blocking `unix.Read` / `unix.Write` on the fd.

---

## Lab topology

```mermaid
flowchart TB
  mac["Mac host"]
  docker["Docker: mytcp-lab<br/>NET_ADMIN + /dev/net/tun"]
  shell1["shell 1: /tmp/mytcp"]
  shell2["shell 2: ping / nc"]

  mac -->|"make lab-up / shell"| docker
  docker --> shell1
  docker --> shell2
  shell2 -->|"10.0.0.1 → 10.0.0.2 via tap0"| shell1
```

Same netns: both shells share `tap0`. The stack process is the peer host;
`ping`/`nc` are clients of the kernel address on that iface.

---

## What we deliberately do not own

See the full matrix in [IMPLEMENTATION.md](IMPLEMENTATION.md). Headline gaps:

- **No flow-control enforcement** — peer `Window` is stored, not applied on send  
- **No congestion window** — fixed RTO retransmit only  
- NIC drivers / interrupts / DMA (`myos` territory)  
- Full RFC TCP (SACK, window scale, RTT estimator, simultaneous open, …)  
- UDP, IPv6, fragmentation, routing beyond on-link TAP  
- Kernel socket API — that is what `../c/02_tcp_server.c` uses instead  

Mental model: **sockets hide these bytes; TAP forces you to speak them.**
The demo proves small ping/`nc` paths, not a complete TCP.
