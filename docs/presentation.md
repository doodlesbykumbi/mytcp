# Talk: mytcp — 60-minute session

Companion: [README](../README.md) · [ARCHITECTURE](../ARCHITECTURE.md) ·
[IMPLEMENTATION](../IMPLEMENTATION.md) · [ROADMAP](../ROADMAP.md)

**Reveal deck:** [talk/index.html](talk/index.html) — run `make talk` then open
http://127.0.0.1:8766/ (arrows · F fullscreen · S speaker notes).

**Reasoning essay (non-slides):** [layers-and-onions.md](layers-and-onions.md) —
motivation, giants/foresight, and what “same interface” means (the onion:
Decode/Encode structs + limited ops + nested payload).

Use this file as the **outline / speaker notes source**. The deck follows it.

---

## Title options

1. **From TAP to `curl`: Owning the Bytes Between You and the Network**
2. **Standing on Giants: Why the Network Stack Still Matters**
3. **What `socket()` Hides — and What Protocol Design Made Possible**

Recommended for this framing:

> **Standing on Giants: Building a Userspace TCP Stack (and Why the Layers Still Matter)**

---

## Session goals (say these out loud once)

By the end, attendees should feel:

1. **Motivation** — why peel open something that “already works”
2. **Framing** — this is teaching infrastructure, not a product stack
3. **Humility** — incredible systems are aggregations; we stand on giants
4. **Foresight** — protocols were designed to *roll out* and to *leave doors open*
5. **Pattern** — at every layer the interface rhyme is the same
6. **Concrete** — TAP → ARP → IP → TCP → HTTP → (optional) TLS, live or recorded

---

## Visual device: the layer board

Keep **one persistent slide layout** (or a physical whiteboard) for most of
the talk. Start almost empty; populate as you go.

### Stub board (show first — nearly blank)

```text
┌─────────────────────────────────────────────────────────┐
│  APPLICATION                                            │
│  (  )                                                   │
├─────────────────────────────────────────────────────────┤
│  SECURITY / SESSION   (optional)                        │
│  (  )                                                   │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT                                              │
│  (  )                                                   │
├─────────────────────────────────────────────────────────┤
│  NETWORK                                                │
│  (  )                                                   │
├─────────────────────────────────────────────────────────┤
│  LINK                                                   │
│  (  )                                                   │
├─────────────────────────────────────────────────────────┤
│  WIRE / DEVICE                                          │
│  (  )                                                   │
└─────────────────────────────────────────────────────────┘
         ↑ same shape at every layer: bytes in → decide → bytes out
```

### Progressive fills (one slide each, or animate on one slide)

| Beat | Fill in |
|------|---------|
| After “socket hides” | Wire: `TAP fd` — Ethernet frames |
| After L2 | Link: Ethernet demux + **ARP** |
| After ping | Network: **IPv4** + **ICMP** |
| After handshake | Transport: **TCP** (minimal) |
| After curl | App: **HTTP/1** |
| After https | Optional: **TLS** (`crypto/tls` *or* our `mintls`) |

### Final board (leave up during Q&A)

```text
┌─────────────────────────────────────────────────────────┐
│  APPLICATION     HTTP/1  (GET/HEAD, Connection: close)  │
├─────────────────────────────────────────────────────────┤
│  SECURITY        TLS 1.2 optional  (stdlib │ mintls)    │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT       TCP  (handshake, data, FIN, RTO)       │
├─────────────────────────────────────────────────────────┤
│  NETWORK         IPv4 + ICMP echo                       │
├─────────────────────────────────────────────────────────┤
│  LINK            Ethernet II + ARP                      │
├─────────────────────────────────────────────────────────┤
│  WIRE            Linux TAP  (not TUN)                   │
└─────────────────────────────────────────────────────────┘
```

**Speaker line to repeat:**  
*“Notice: every box speaks in bytes. The meaning changes; the shape doesn’t.”*

---

## 60-minute rundown

| Block | Time | Agenda |
|-------|------|--------|
| A | 0:00–0:08 | Motivation & framing |
| B | 0:08–0:18 | Giants, aggregation, protocol foresight |
| C | 0:18–0:22 | The interface rhyme + stub board |
| D | 0:22–0:38 | Populate the stack (TAP → HTTP), one rabbit hole per layer |
| T | 0:38–0:46 | Deep dive: peeling TLS (records, handshake, keys, AEAD) |
| E | 0:46–0:52 | Live demo (or recording) |
| F | 0:52–0:55 | Doors left open + “every layer is a discipline” |
| G | 0:55–1:00 | Takeaways + Q&A seed |

Buffer: if demo slips, cut F to 1 minute and keep Q&A. If T runs long,
drop the “Sealing a record” slide first.

---

## Block A — Motivation & framing (8 min)

### Slide A0 — How I got here
**Title:** How I got here

**Visual:** two story cards side by side, then a punch line.

**Say:**  
At KubeCon I watched a network engineer from Oracle stitch together all
kinds of networks from primitives, live, to explain container networking.
Networking stopped looking like magic; it was parts you could compose.
Later, at AWS re:Invent, I watched a talk on **SRD** (Scalable Reliable
Datagram), the transport AWS runs on its Nitro cards. That made it click
that TCP is a choice, not a law of nature. So I wanted to own the bytes
myself, from the wire up.

### Slide A1 — Hook
**Title:** What happens when you type `curl`?

**Visual:** One line of shell → black box labeled “kernel / stack / magic”

**Say:**  
We treat networking as a syscall. Something answers ARP, stamps IP,
runs a handshake, retransmits. Today we take that black box apart—
not to replace the kernel, but to *see*.

### Slide A2 — Motivation
**Title:** Why reimplement what already works?

Keep to four bullets:

- **Curiosity with teeth** — Wireshark fields become *your* structs
- **Debugging empathy** — timeouts, MTU, TLS alerts stop being folklore
- **Systems literacy** — cloud, mesh, eBPF, QUIC all assume this vocabulary
- **Joy** — `ping` lighting up *your* process is a memorable win

**Avoid:** “kernel stacks are bad.” You’re learning, not competing.

### Slide A3 — Framing the effort
**Title:** What this project is (and isn’t)

| Is | Isn’t |
|----|-------|
| A teaching stack over Linux **TAP** | A production TCP |
| Staged: each layer unlocks a demo | Full windowing / congestion / routing |
| Honest about gaps ([IMPLEMENTATION](../IMPLEMENTATION.md)) | “We reinvented AWS” |

**Say:**  
The effort is deliberately *bounded*. Bounded work is how you finish—
and how you respect the giants who spent decades on the rest.

### Slide A4 — The lab picture
**Title:** Kernel on one side, us on the other

**Visual:** `ping/curl` → kernel → `tap0` ↔ our Go process

**Say:**  
TAP gives us Ethernet frames. TUN would skip L2. We chose TAP so ARP
isn’t optional mythology.

---

## Block B — Giants, aggregation, foresight (10 min)

### Slide B1 — Standing on the shoulders of giants
**Title:** Nothing here was invented alone

**Say:**  
Ethernet, IP, TCP, HTTP, TLS — each is a *negotiation* across companies,
RFCs, failures, and decades. Our repo is a few thousand lines standing
on millions of hours of prior art. That’s not a caveat; that’s the point.

**Visual idea:** small figure on a stack of RFCs / timeline 1970s→now

### Slide B2 — Aggregation of efforts
**Title:** Incredible things are aggregates

- Protocols compose: L2 doesn’t know HTTP; HTTP doesn’t know ARP
- Implementations compose: NIC firmware, kernel, TLS library, curl, CDN
- Organizations compose: vendors interoperated because specs were *shared*

**Say:**  
When we build `mytcp`, we’re not proving we’re cleverer than the kernel.
We’re proving the *interfaces* were clear enough that a learner can plug in.

### Slide B3 — Foresight: designed to roll out
**Title:** Protocols that could ship — then grow

Pick 2–3; don’t lecture:

- **IP** — “best effort” + higher layers for reliability → Internet scales
- **TCP** — ports + byte streams → countless apps without rewriting IP
- **TLS** — *above* TCP, not baked into it → encrypt when you need it
- **Extension points** — EtherType, IP protocol number, TCP options, TLS versions

**Say:**  
The foresight wasn’t predicting AWS. It was leaving **seams**—stable
contracts so the future could arrive without rewriting the past.

### Slide B4 — Doors left open: SRD
**Title:** AWS swapped the transport and kept the TCP API

**Say:**  
SRD (Scalable Reliable Datagram) runs on the AWS Nitro card, close to the
wire. It sprays one flow's packets across many network paths, retransmits
in microseconds, and delivers reliably but **out of order**, leaving order
restoration to the layer above. EFA exposes SRD directly for HPC and ML.
ENA Express carries your ordinary TCP and UDP flows between instances over
SRD, transparently. The TCP API at the edge stays the same while a
different transport does the work in the middle.

**Follow-up slide (B4b):** stacked diagram — app → TCP socket → Nitro/SRD →
many fabric paths → peer Nitro reorders → TCP bytes up.

**Punchline:**  
TCP is not mandatory everywhere. TLS is not mandatory everywhere.
The **stack** is what lets you slot technology in—or leave it out.

**Sources (for Q&A):** AWS, “A Cloud-Optimized Transport Protocol for
Elastic and Scalable HPC” (IEEE Micro, 2020); AWS EFA and ENA Express docs.

### Slide B5 — TLS as the optional door
**Title:** Encryption is a layer, not a religion

```text
  HTTP  ──┬── plain on TCP        (-app http)
          └── TLS then HTTP       (-app https / https-diy)
                 ↑
            same TCP below
```

**Say:**  
We added HTTPS two ways: glue to Go’s `crypto/tls`, then a tiny DIY TLS 1.2.
Both sit on the *same* stream interface. That’s foresight paying rent
in a teaching demo.

---

## Block C — The interface rhyme (4 min)

### Slide C1 — Same shape every time (the onion)
**Title:** Bytes in → demux / decide → bytes out

**Clarify:** Not one Go `interface` type — each protocol is a **struct**
with **Decode / Encode**, a **small verb set**, and a **payload** that is
the next layer. That shared habit *is* the onion interface.
(See [layers-and-onions.md](layers-and-onions.md).)

| Layer | “Read” | “Write” |
|-------|--------|---------|
| TAP | Ethernet frame | Ethernet frame |
| Eth/ARP | Frame | Frame (reply) |
| IPv4 | Datagram | Datagram |
| TCP | Segment / stream | Segment / stream |
| TLS | Records → cleartext | Cleartext → records |
| HTTP | Request bytes | Response bytes |

**Say:**  
Once students see the rhyme, the stack stops being a tower of trivia
and becomes a *habit of mind*.

### Slide C2 — Stub board again
**Title:** We’ll fill this in together

Show empty stubs. Promise: no layer gets a novel until the one below works.

---

## Block D — Populate the stack (20 min)

*Reuse the layer board; add one box per slide. Keep each beat tight.*

### Slide D0 — Every stage ended with a working demo
**Title:** One demo per layer ([ROADMAP](../ROADMAP.md))

`dump` → `ping` → `nc` → `curl` → `curl -k`

### Slide D1 — Wire: TAP
**Fill:** WIRE = Linux TAP (`IFF_TAP|IFF_NO_PI`)  
**Why not TUN?** Need Ethernet + ARP.  
**Why Docker on Mac?** No stock TAP on macOS; lab keeps the story clean.  
**Rabbit holes:** kernel networking internals, virtual NICs (veth, TAP, macvlan), XDP / eBPF, NIC offloads.

### Slide D2 — Link: Ethernet + ARP
**Fill:** LINK = EtherType demux + ARP who-has / is-at  
**Demo line:** First ping is really an ARP story.  
**Rabbit holes:** switching and MAC learning, VLANs, spanning tree, ARP spoofing, the Wi-Fi MAC layer.

### Slide D3 — Network: IPv4 + ICMP
**Fill:** NETWORK = IPv4 header + ICMP echo  
**Teaching moment:** checksum as “did we mean these bytes?”  
**Rabbit holes:** routing (OSPF, BGP), IPv6, NAT, MTU and fragmentation, how traceroute works.

### Slide D4 — Transport: TCP (honest)
**Fill:** TRANSPORT = passive open, handshake, in-order data, FIN, fixed RTO  
**Honest slide:** window *field* ≠ congestion control; no real routing.  
**Rabbit holes:** congestion control (Reno, CUBIC, BBR), flow control, SACK, QUIC, SRD.

### Slide D5 — App: HTTP/1
**Fill:** APPLICATION = tiny HTTP/1 on the byte stream  
**Say:** TCP doesn’t know HTML. It only promises ordered bytes.  
**Rabbit holes:** keep-alive → HTTP/2 multiplexing → HTTP/3 on QUIC, caching, REST and gRPC.

### Slide D6 — Optional: TLS
**Fill:** SECURITY = optional  
Two doors: **stdlib** vs **mintls** (one cipher suite, our records/handshake).  
**Say:** Same `StreamConn` underneath—pluggable by design. Then go into Block T.

### Slide D7 — Code map (30 seconds)
**Title:** Where to look in the repo

```text
internal/tap → eth → arp → ip4/icmp → tcp → http1 / mintls
internal/stack   demux glue
```

---

## Block T — Deep dive: peeling TLS (8 min)

*TLS is the layer where a whole discipline (cryptography) shows through.
Goal: the audience can name the four jobs and knows where to read next.*

### Slide T1 — TLS is its own onion
Record header: type (1) · version (2) · length (2) · payload.
Content types 20 CCS, 21 Alert, 22 Handshake, 23 AppData. Show `readRecord`
from `internal/mintls/record.go`. **Say:** same habit as Ethernet, but riding on a
byte stream instead of a frame.

### Slide T2 — The handshake (TLS 1.2, ECDHE)
ClientHello → ServerHello, Certificate, ServerKeyExchange, ServerHelloDone →
ClientKeyExchange, ChangeCipherSpec, Finished → ChangeCipherSpec, Finished.
**Say:** two round trips before any HTTP; TLS 1.3 cuts it to one.

### Slide T3 — Three jobs, three kinds of crypto
| Job | In mintls |
|-----|-----------|
| Key agreement | ECDHE on P-256 |
| Authentication | ECDSA signature + X.509 certificate |
| Key derivation | TLS 1.2 PRF (HMAC-SHA256) |
| Record protection | AES-128-GCM (AEAD) |

### Slide T4 — Agreeing on a secret nobody sent
`ecdh.P256().GenerateKey` → signed ServerKeyExchange → `ecdhe.ECDH(clientPub)`.
**Say:** ephemeral keys give forward secrecy.

### Slide T5 — One secret, many keys
`masterSecret` and `keyBlock` from `prf.go`; Finished = PRF over the transcript
hash, so tampering with any handshake byte fails.

### Slide T6 — Sealing a record
Nonce = fixed IV (4) + sequence (8); AAD = seq · type · version · length.
**Say:** header is authenticated, not encrypted; reorder/replay/bit-flip → tag fails.

### Slide T7 — What we wrote vs what we borrowed
Wrote: record framing, handshake state machine, transcript + Finished, PRF.
Borrowed from `crypto/*`: AES, GCM, ECDH, ECDSA, SHA-256, HMAC, X.509.
**Say:** build the protocol to learn it; never hand-roll the primitives.

### Slide T8 — Honest scope, and what 1.3 changed
Not in mintls: more suites, resumption, client certs, alerts, side-channel audit.
TLS 1.3: 1-RTT (0-RTT optional), encrypted certificate, HKDF, AEAD only,
forward secrecy mandatory.
**Rabbit holes:** elliptic-curve math, AEAD design, PKI / cert chains /
Certificate Transparency, side channels, post-quantum key exchange (hybrid ML-KEM).

---

## Block E — Demo (8 min)

### Slide E1 — Demo agenda
1. `make lab-up && make lab-build`
2. Run `-app http` (or `https-diy`)
3. `ping 10.0.0.2` → `curl http://10.0.0.2/`
4. Optional: packet inspector (`make ui` + `captures/latest.jsonl`)

### Demo commands

```bash
make lab-up
make lab-build
# shell A
/tmp/mytcp -i tap0 -app http -dump=false -pcap captures/latest
# shell B
ping -c 3 10.0.0.2
curl http://10.0.0.2/
# optional DIY TLS
# /tmp/mytcp -i tap0 -app https-diy -dump=false
# curl -k --tlsv1.2 --tls-max 1.2 https://10.0.0.2/
```

**Backup:** pre-recorded terminal + inspector if Docker fails.

### Slide E2 — What you just saw
Ping = ARP + ICMP. Curl = ARP + IP + TCP + HTTP.  
HTTPS = same path with an optional session layer inserted.

---

## Block F — Doors open (3 min)

### Slide F1 — What we can slot next
Without rewriting Ethernet:

- Better TCP (windowing, congestion)—or stop and teach with honesty
- QUIC / UDP experiments beside TCP
- Policy / tracing at the demux boundary
- TLS 1.3, or keep mintls as a simple TLS 1.2 example

### Slide F2 — Industry rhyme
**Title:** The same idea at planetary scale

Layers let operators replace guts (optics, fabrics, load balancers, TLS
terminators) while apps keep speaking “reliable bytes” or “datagrams.”
Your teaching stack is a pocket-sized version of that idea.

### Slide F3 — Every layer is a discipline
| Layer | We built | Where people spend careers |
|-------|----------|----------------------------|
| Wire | TAP fd | kernel networking, eBPF/XDP, NIC hardware |
| Link | Ethernet + ARP | switching, VLANs, data-center fabrics |
| Network | IPv4 + ICMP | routing (BGP), IPv6, NAT, SDN |
| Transport | minimal TCP | congestion control, QUIC, SRD, RDMA |
| Security | mintls (TLS 1.2) | cryptography, PKI, protocol analysis |
| Application | HTTP/1 | HTTP/2–3, APIs, CDNs, caching |

**Say:** peeling the onion once gives you a map. Pick a layer and keep digging.

---

## Block G — Close (5 min)

### Slide G1 — Takeaways (leave on screen)
1. **Own the bytes once** — magic becomes a sequence of headers
2. **Respect the aggregate** — we stand on giants; finishing small is wisdom
3. **Seams > omniscience** — protocols rolled out because they left doors open
4. **Same interface rhyme** — bytes in, decide, bytes out—at every layer
5. **Optional is powerful** — TLS on top of TCP is a feature of the design

### Slide G2 — Q&A prompts (if silence)
- Why TAP instead of hijacking `lo`?
- What’s the first TCP feature you’d add next—and why might you *not*?
- Where else do you see “optional layers” (auth, compression, RPC)?

### Slide G3 — Links
Repo path, ARCHITECTURE, IMPLEMENTATION (“honest matrix”), smoke test.

---

## Progressive slide checklist (build order)

1. Title  
2. Goals (5 bullets)  
3. Hook: curl → black box  
4. Motivation  
5. Is / isn’t  
6. Lab diagram (TAP)  
7. Giants  
8. Aggregation  
9. Foresight / seams  
10. Backbone / slotting tech (careful wording)  
11. TLS optional diagram  
12. Interface rhyme table  
13. **Empty layer board**  
14–20. Board fills: TAP, Eth/ARP, IP/ICMP, TCP, HTTP, TLS, repo map  
21. Demo agenda  
22. Demo (live)  
23. What you saw  
24. What we can slot next  
25. Takeaways  
26. Q&A / links  

---

## Timing if you run long

| Cut | Recover |
|-----|---------|
| Shorten Block B examples | Keep B4 + B5 (foresight + TLS optional) |
| Skip mintls detail | Show only “TLS is a layer” |
| Skip packet UI | `curl` + log lines enough |
| Skip DIY TLS demo | Mention `-app https-diy` exists |

---

## Abstract (CFP / meetup blurb)

When you call `curl`, you’re standing on decades of shared protocol design—
Ethernet, IP, TCP, HTTP, optionally TLS—each layer a contract that let the
Internet *roll out* and still leave doors open for whatever came next.
This talk peels that stack open by building a small userspace
Ethernet→IP→TCP stack in Go over a Linux TAP device, then hanging HTTP
and an optional TLS layer on the same stream interface.

We’ll frame the effort honestly (teaching stack, not production TCP),
celebrate how incredible systems are aggregations of prior work, and
watch the same “bytes in → decide → bytes out” rhyme at every layer—
populating a stubbed stack diagram as we go from ARP to `curl` (and
`curl -k`). Takeaway: foresight in protocol design isn’t predicting the
future; it’s leaving seams so the future can plug in.

---

## Speaker bio (template)

> I’m [Name], a [role] in [city]. I learn systems by reimplementing the
> parts we usually treat as magic—recently a userspace TCP/IP stack over
> Linux TAP in Go, including a tiny DIY TLS 1.2 path. I care about
> inspectable networks: bytes on the wire, honest limits, and demos
> you can re-run.

---

## Tech requirements

- HDMI/USB-C; speaker laptop for live demo  
- Docker available **or** recorded fallback  
- Browser optional for packet UI  
- Pre-pull lab image / rehearse smoke once day-of  

---

## Shorter formats (if needed)

| Duration | How to cut |
|----------|------------|
| **45 min** | A(5) + B(7) + C(3) + D(15) + E(8) + G(7); fold F into B5 |
| **20 min lightning** | Hook → empty board → fill TAP/ARP/TCP/HTTP in 10 min → one curl → takeaways |

---

## One-line closer (optional)

> We didn’t invent the Internet in an afternoon—and that’s the gift.
> Someone left us layers. Our job is to understand them well enough
> to build on them—or to know when to leave a layer optional.
