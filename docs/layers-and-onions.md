# Layers, onions, and standing on giants

Working notes — not a talk deck. The goal is to pin down *why* this
project feels coherent, so the presentation and the code can stay honest
to the same idea.

Companion: [ARCHITECTURE](../ARCHITECTURE.md), [IMPLEMENTATION](../IMPLEMENTATION.md),
[presentation](presentation.md), [Reveal deck](talk/index.html) (`make talk`).

---

## 1. Motivation

Two talks started this. At KubeCon, a network engineer from Oracle
stitched together all kinds of networks from primitives, live, to
explain container networking. Networking stopped looking like magic;
it was parts you could compose. Later, at AWS re:Invent, a talk on SRD
showed that even the transport layer is swappable at hyperscale. TCP is
a choice, not a law of nature. I wanted to earn that intuition by
building the parts myself.

Calling `curl` or `ping` hides a long chain of work: Ethernet framing,
ARP, IPv4, ICMP or TCP, maybe TLS, then HTTP. The kernel (or a library)
does that so applications can pretend the network is a file-like stream
or a simple request/response.

Reimplementing a slice of that stack over a TAP device is not about
beating the kernel. It is about making the hidden chain *legible*:

- Wireshark fields become structs you wrote.
- Timeouts and checksums stop being folklore.
- Cloud vocabulary (MTU, handshake, termination, offload) attaches to
  something you have touched.

The effort is deliberately bounded. A teaching stack that stops at
“enough for `ping` / `nc` / `curl` / `curl -k`” respects the decades of
work we are *not* rewriting. Finishing small is part of the point.

---

## 2. Incredible things are aggregates

Nothing in `mytcp` was invented here in any deep sense. Ethernet, IP,
TCP, HTTP, and TLS are the product of RFCs, committees, vendor fights,
failed experiments, and slow convergence on shared contracts.

What we *do* invent is a small Go process that speaks enough of those
contracts to light up demos. That only works because the contracts were
written down and layered. The repo is a few thousand lines standing on
an enormous pile of prior art. That is not a disclaimer; it is the
central observation:

**Impressive systems are usually aggregations of efforts**, not lone
strokes of genius. Learning by reimplementation is how you feel the
seams between those efforts.

The same pattern shows up above the packet:

- NIC firmware + kernel + userspace stack + TLS library + curl + CDN
- Organizations that interoperated because the *spec* was shared

When a learner can plug a TAP fd into Ethernet → ARP → IP → TCP → HTTP,
that is evidence the interfaces were clear enough to stand on.

---

## 3. Foresight: roll out, then leave doors open

Protocol design at its best did two jobs at once:

1. **Ship something** that could roll out across heterogeneous machines.
2. **Leave seams** so later technology could plug in without rewriting
   the past.

Examples that matter for this project:

| Seam | What it enabled |
|------|-----------------|
| IP as best-effort datagrams | Reliability can live above (TCP) or elsewhere |
| TCP as a byte stream + ports | Unlimited apps without changing IP |
| EtherType / IP protocol / port | Demux to the next handler without one god-packet |
| TLS *above* TCP, not inside it | Encryption is optional; cleartext HTTP still valid |
| Version and extension fields | TLS 1.2 → 1.3, TCP options, IPv6 beside IPv4 |

Foresight here is not “they predicted AWS.” It is that they left
**replaceable contracts**. AWS’s SRD (Scalable Reliable Datagram) is the
clearest example I know of. It runs on the Nitro card, sprays one flow’s
packets across many network paths, retransmits in microseconds, and
delivers reliably but out of order, leaving order restoration to the
layer above. With ENA Express, ordinary TCP flows between instances ride
over SRD transparently: the TCP API at the edge is unchanged while a
different transport does the work in the middle.

That only works because the edge contract (a reliable byte stream) and
the mechanism underneath were separable. TCP is not mandatory
everywhere. TLS is not mandatory everywhere. The stack idea is what lets
you **slot technology in — or leave it out**.

In this repo that shows up concretely:

```text
HTTP  ──┬── our server on net.Listener      (-app http)
        ├── net/http.Server on same Listener (-app http-go)
        └── TLS, then HTTP                   (-app https | https-go | https-diy)
               ↑
          same TCP / StreamConn below
```

TLS was never required for the teaching path. Adding it later did not
require redesigning Ethernet. That is the door working as designed.

---

## 4. What “interface” means here (the onion)

In the presentation notes, “same interface at each layer” is easy to
misread as “same Go `interface` type” or “same `net.Conn` everywhere.”
That is not the claim.

The claim is about an **onion-shaped protocol habit**:

> Each layer is a **header + payload**.  
> Each layer has a **struct** (or message type) with **Decode / Encode**  
> and a **small set of operations**.  
> The payload of layer *N* is the whole message of layer *N+1*.  
> Demux is usually a type field that selects the next decoder.

That is the onion. `internal/dump` literally peels it for debugging;
the stack peels it for real.

### 4.1 The shared shape in this codebase

Look at the leaf packages — they rhyme on purpose:

| Package | Type | Decode | Encode | Nesting / demux |
|---------|------|--------|--------|-----------------|
| `eth` | `Frame` | `Decode` | `Encode` | `Type` → ARP or IPv4; `Payload` |
| `arp` | `Packet` | `Decode` | `Encode` | Fixed L2.5 message (no further nest) |
| `ip4` | `Packet` | `Decode` | `Encode` | `Proto` → ICMP/TCP; `Payload` |
| `icmp` | `Echo` | `Decode` | `Encode` | Reply is a tiny transform |
| `tcp` | `Segment` | `Decode` | `Encode` | Ports + flags; `Payload` is the stream |
| `mintls` | records / HS msgs | read/decode | write/encode | ContentType → handshake / app data |
| `http1` | buffered request | decode lines | format response | App bytes on the stream |

Almost every layer:

1. **Names the header fields** in a struct.
2. **Decodes** opaque bytes → struct (validate length, version, etc.).
3. **Encodes** struct → bytes (often computing checksums on the way out).
4. Treats **`Payload` as the next onion layer** (or as opaque app data).
5. Exposes only a **limited verb set**: decode, encode, maybe
   “reply to this” (ARP reply, ICMP echo reply), maybe
   “handle this segment” (TCP). Not a kitchen-sink API.

TCP and TLS grow a *session* on top of that habit (conn table, crypto
state). The onion still holds for the on-the-wire unit (`Segment`,
TLS record). HTTP sits even higher: it assumes a bidirectional byte
pipe and only then imposes request/response framing.

### 4.2 Why the rhyme matters for reasoning

Once you see Decode/Encode + payload + type-field demux, the stack stops
being a tower of unrelated trivia:

- **Learning path** — implement Ethernet before ARP replies; IP before
  ICMP; segments before a stream API; stream before HTTP; stream before TLS.
- **Honesty** — if a layer lacks real windowing or congestion control,
  that is a gap in *operations*, not a failure of the onion shape.
- **Extension** — new tech usually means a new struct with the same
  habit, plugged in at a demux point (new EtherType, new IP proto,
  new port, optional session above TCP).
- **Debugging** — the dump onion and the live stack use the same peel
  order; the UI and the code agree.

You can argue that **every classical Internet protocol in this project
shares the onion interface**, even though they do not share one Go
interface type. The similarity is structural, not nominal.

### 4.3 What is *not* the onion

A few things sit beside the peel-and-wrap habit:

- **TAP device** — `Read`/`Write` of frames. That is the wire handle,
  not a protocol header.
- **`tcp.Listener` / `StreamConn`** — `net.Listener` / `net.Conn` over
  userspace TCP: adapters *above* segments. They consume the onion’s top
  payload as a byte stream.
- **`stack` demux** — glue that calls `eth.Decode`, switches on type,
  calls the next `Decode`. The onion lives in the protocols; the stack
  is the peeler.

Keeping those distinct helps: protocols are onions; the runtime is what
walks the onion.

### 4.4 A compact statement

**Onion interface (working definition):**

> A protocol layer is a typed message with encode/decode, a small set of
> meaningful operations, and a payload that is either opaque or another
> protocol message. Layers compose by encapsulation and demultiplexing,
> not by merging into one mega-header.

That is what “the interface is sort of the same at each level” was
meant to name.

### 4.5 TLS: an onion with cryptography inside

`mintls` is the clearest test of the onion idea, because TLS is itself
layered. The TCP byte stream carries **records**: a 5-byte header (type,
version, length) and a payload. The type field demuxes into sub-protocols
(20 ChangeCipherSpec, 21 Alert, 22 Handshake, 23 Application data), the
same move as EtherType or the IP protocol number. Handshake messages are
onions again: a type byte, a 3-byte length, a body.

What is new at this layer is that the operations are cryptographic. The
handshake does four separate jobs, and each one is its own field:

| Job | Question | In mintls |
|-----|----------|-----------|
| Key agreement | Share a secret over a public wire | ECDHE on P-256 |
| Authentication | Is this the right server? | ECDSA signature, X.509 cert |
| Key derivation | Turn one secret into many keys | TLS 1.2 PRF (HMAC-SHA256) |
| Record protection | Confidentiality and integrity | AES-128-GCM (AEAD) |

The line between what we wrote and what we borrowed matters. We wrote
the record framing, the handshake state machine, the transcript hash and
Finished checks, and the PRF/key schedule. Go's `crypto/*` gives us AES,
GCM, ECDH, ECDSA, SHA-256 and X.509. That split is the right one: the
protocol is learnable by building it, but primitives need constant-time
code and years of review.

Two details show how the layers still cooperate. The AEAD's additional
data is the sequence number plus the record header, so the header is
authenticated even though it stays in cleartext. And Finished is a PRF
over the hash of every handshake byte, so tampering anywhere in the
handshake is caught at the end.

### 4.6 Every layer is a discipline

Building one thin slice of each layer gives a map, not mastery. Behind
each layer is a field where people spend whole careers:

| Layer | We built | Where to dig |
|-------|----------|--------------|
| Wire | TAP fd | kernel networking, eBPF/XDP, NIC offloads |
| Link | Ethernet + ARP | switching, VLANs, spanning tree, DC fabrics |
| Network | IPv4 + ICMP | routing (OSPF, BGP), IPv6, NAT, MTU |
| Transport | minimal TCP | congestion control (CUBIC, BBR), QUIC, SRD, RDMA |
| Security | mintls (TLS 1.2) | ECC, AEAD design, PKI and CT, side channels, post-quantum KEMs |
| Application | HTTP/1 | HTTP/2 and 3, caching, CDNs, API design |

The onion is what makes that map usable: because each layer only talks
to its neighbours through a payload, you can go deep on one without
first mastering the others.

---

## 5. How this frames the effort

Putting the pieces together:

1. **Motivation** — make the hidden chain legible; joy when `ping` hits
   *your* process.
2. **Framing** — teaching stack with honest gaps; not a product TCP.
3. **Humility** — we stand on giants; aggregates beat lone genius myths.
4. **Foresight** — seams let the Internet roll out *and* let later tech
   (or optional TLS) slot in.
5. **Onion interface** — Decode/Encode structs, limited ops, payload
   nesting; the rhyme that makes the stack learnable and extensible.

The presentation can animate an empty layer board filling in. This
document is the reason that animation is not just theater: each fill is
another onion skin with the same habit, standing on contracts we did not
author but can finally see.

---

## 6. Open questions to keep chewing on

- Where does the onion stretch thin? (TCP streams, TLS epochs, HTTP
  framing over cleartext — still onions, but the “payload” becomes a
  long-lived pipe.)
- Is QUIC a rebuke to the onion or another onion with different
  layering (UDP + crypto + streams in one deployment unit)?
- Is SRD replacing a layer or collapsing layers? It keeps TCP as the
  host-facing API but moves reliability into the NIC and drops in-order
  delivery. Does the *idea* of seams still hold when the seam moves into
  hardware?
- What would an SRD-style toy look like here: multipath and
  out-of-order reliable datagrams over UDP, beside `tcp`?
- Should `mytcp` ever introduce a formal Go `interface` for
  `Decode`/`Encode`, or would that fake unity the RFCs never required?

No need to answer these for the talk. They are compass headings for
later reasoning.
