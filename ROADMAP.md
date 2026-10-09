# mytcp roadmap

We grow a userspace TCP/IP stack **one layer at a time** over a Linux
**TAP** device (Ethernet frames). The host kernel only moves bytes; we
own ARP → IPv4 → ICMP → TCP.

Companion: sockets in `../c/02_tcp_server.c` use the *kernel* TCP.
This project implements the bytes those syscalls hide.

Run live TAP under Linux (Docker on macOS). Decode unit tests run anywhere.

---

## Stage 0 — TAP + hex dump *(done)*

Open `/dev/net/tun` with `IFF_TAP|IFF_NO_PI`. `read`/`write` are raw
Ethernet frames. `-dump-only` prints every RX frame and replies to nothing.

```text
[dst MAC 6][src MAC 6][EtherType 2][payload…]
```

| What works | What hurts |
|------------|------------|
| See real frames from the host | No replies → host ARP/pings time out |
| No protocol assumptions | Need `CAP_NET_ADMIN` + Linux |

---

## Stage 1 — Ethernet + ARP *(done)*

Decode Ethernet II. When the host ARPs for our IP, reply with our MAC
so the kernel can send IPv4 to us.

| What works | What hurts |
|------------|------------|
| Host learns IP→MAC | No IP yet → still no ping |

---

## Stage 2 — IPv4 + ICMP echo *(done)*

Decode IPv4; answer ICMP echo requests. `ping 10.0.0.2` works.

| What works | What hurts |
|------------|------------|
| Round-trip ICMP | No UDP/TCP; no fragmentation |

---

## Stage 3 — TCP handshake *(done)*

Passive open on one port (`-tcp 7`). SYN → SYN-ACK → ACK → ESTABLISHED.
One connection table keyed by 4-tuple. RST for unexpected segments.

| What works | What hurts |
|------------|------------|
| `nc` can connect | No data path yet (empty ESTABLISHED) |

---

## Stage 4 — TCP data echo *(done)*

In-order payload advances `rcv_nxt`. We ACK and echo bytes (PSH+ACK).
Out-of-order → duplicate ACK only (peer retransmits).

| What works | What hurts |
|------------|------------|
| Line echo over TAP | No receive reassembly queue; tiny feature set |

---

## Stage 5 — Retransmit *(done)*

Unacked segments sit on an outstanding queue. A 100ms tick retransmits
after RTO (500ms), up to 5 tries. Pure ACKs are not queued.

| What works | What hurts |
|------------|------------|
| Survives lossy demos / slow peers | Fixed RTO, no RTT estimate, no congestion window |

---

## Stage 6 — HTTP/1 on TCP *(done)*

Apps reach TCP through `Stack.Listen(port)`, a `net.Listener` whose
`Accept` returns a `net.Conn` (`StreamConn`). Default `-app http`
listens on `:80`, buffers to `\r\n\r\n`, answers GET/HEAD, then FINs
(`Connection: close`). `-app echo` keeps Stage 4 behaviour on `:7`.

| What works | What hurts |
|------------|------------|
| `curl http://10.0.0.2/` | No request body, chunked, keep-alive, TLS, routes |

---

## Stage 7 — Client side *(done)*

`Stack.Dial` sends the first SYN (SYN_SENT), so mytcp can connect out.
An ARP cache and a one-gateway route find the next hop's MAC.
`stack.DialContext` plugs into `http.Transport`, so `-get URL` is Go's own
`http.Client` on our TCP; `-dial host:port` is nc. Through the lab's NAT
(`make lab-nat`) it reaches the internet. Host names go through our own
UDP and a hand-rolled DNS stub resolver, so the whole client path makes
no kernel socket calls; `make smoke-internet` proves it with strace.

| What works | What hurts |
|------------|------------|
| `mytcp -get https://www.google.com/` | No MSS option, no OOO reassembly, A-only DNS, no cache |

---

## Not yet

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the full yes/partial/no matrix.

Headline gaps called out there: **flow-control window enforcement**,
**congestion window**, window scaling, SACK, OOO reassembly, RTT-based RTO,
UDP, IPv6, fragmentation, TLS, full HTTP/1.1.
