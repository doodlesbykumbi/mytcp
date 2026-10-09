/* Layer decode for mytcp JSONL captures — Ethernet → ARP/IPv4 → ICMP/TCP → HTTP */

export function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function decodeFrame(bytes) {
  const layers = [];
  if (bytes.length < 14) {
    return { summary: `short ${bytes.length}B`, layers, proto: "?" };
  }

  const dst = mac(bytes, 0);
  const src = mac(bytes, 6);
  const type = (bytes[12] << 8) | bytes[13];
  layers.push({
    id: "eth",
    name: "L2 Ethernet",
    summary: `${src} → ${dst}  type=${etherName(type)}`,
    start: 0,
    end: 14,
    color: "var(--c-l2)",
  });

  let summary = etherName(type);
  let proto = etherName(type);

  if (type === 0x0806) {
    const arp = decodeARP(bytes, 14);
    layers.push(...arp.layers);
    summary = arp.summary;
    proto = "ARP";
  } else if (type === 0x0800) {
    const ip = decodeIPv4(bytes, 14);
    layers.push(...ip.layers);
    summary = ip.summary;
    proto = ip.proto;
  } else if (type === 0x86dd) {
    layers.push({
      id: "ipv6",
      name: "L3 IPv6",
      summary: "(not decoded)",
      start: 14,
      end: bytes.length,
      color: "var(--c-l3)",
    });
    summary = "IPv6";
    proto = "IPv6";
  } else {
    layers.push({
      id: "payload",
      name: "Payload",
      summary: `${bytes.length - 14}B`,
      start: 14,
      end: bytes.length,
      color: "var(--c-pay)",
    });
  }

  return { summary, layers, proto, dst, src };
}

function decodeARP(bytes, off) {
  const layers = [];
  if (bytes.length < off + 28) {
    return { summary: "ARP truncated", layers };
  }
  const op = (bytes[off + 6] << 8) | bytes[off + 7];
  const sha = mac(bytes, off + 8);
  const spa = ipv4(bytes, off + 14);
  const tha = mac(bytes, off + 18);
  const tpa = ipv4(bytes, off + 24);
  const opName = op === 1 ? "who-has" : op === 2 ? "is-at" : `op=${op}`;
  const summary =
    op === 1 ? `ARP who-has ${tpa} tell ${spa}` : `ARP ${spa} is-at ${sha}`;
  layers.push({
    id: "arp",
    name: "L3 ARP",
    summary: `${opName}  ${spa} (${sha}) → ${tpa} (${tha})`,
    start: off,
    end: off + 28,
    color: "var(--c-l3)",
  });
  return { summary, layers };
}

function decodeIPv4(bytes, off) {
  const layers = [];
  if (bytes.length < off + 20) {
    return { summary: "IPv4 truncated", layers, proto: "IPv4" };
  }
  const vihl = bytes[off];
  const ihl = (vihl & 0x0f) * 4;
  const total = (bytes[off + 2] << 8) | bytes[off + 3];
  const proto = bytes[off + 9];
  const ttl = bytes[off + 8];
  const src = ipv4(bytes, off + 12);
  const dst = ipv4(bytes, off + 16);
  const endHdr = off + ihl;
  const endPkt = Math.min(bytes.length, off + total);
  layers.push({
    id: "ip",
    name: "L3 IPv4",
    summary: `${src} → ${dst}  proto=${protoName(proto)} ttl=${ttl}`,
    start: off,
    end: endHdr,
    color: "var(--c-l3)",
  });

  const payload = bytes.subarray(endHdr, endPkt);
  if (proto === 1) {
    const icmp = decodeICMP(payload, endHdr);
    layers.push(...icmp.layers);
    return { summary: `${src} → ${dst}  ${icmp.summary}`, layers, proto: "ICMP" };
  }
  if (proto === 6) {
    const tcp = decodeTCP(payload, endHdr);
    layers.push(...tcp.layers);
    return {
      summary: `${src}:${tcp.sport} → ${dst}:${tcp.dport}  ${tcp.summary}`,
      layers,
      proto: tcp.proto,
    };
  }
  layers.push({
    id: "l4",
    name: `L4 ${protoName(proto)}`,
    summary: `${payload.length}B`,
    start: endHdr,
    end: endPkt,
    color: "var(--c-l4)",
  });
  return { summary: `${src} → ${dst}  ${protoName(proto)}`, layers, proto: protoName(proto) };
}

function decodeICMP(payload, absOff) {
  const layers = [];
  if (payload.length < 8) {
    return { summary: "ICMP truncated", layers };
  }
  const type = payload[0];
  const kind =
    type === 8 ? "echo-request" : type === 0 ? "echo-reply" : `type=${type}`;
  layers.push({
    id: "icmp",
    name: "L4 ICMP",
    summary: `${kind} id=${(payload[4] << 8) | payload[5]} seq=${(payload[6] << 8) | payload[7]}`,
    start: absOff,
    end: absOff + 8,
    color: "var(--c-l4)",
  });
  if (payload.length > 8) {
    layers.push({
      id: "icmp-pay",
      name: "payload",
      summary: asciiPreview(payload.subarray(8), 40),
      start: absOff + 8,
      end: absOff + payload.length,
      color: "var(--c-pay)",
    });
  }
  return { summary: `ICMP ${kind}`, layers };
}

function decodeTCP(payload, absOff) {
  const layers = [];
  if (payload.length < 20) {
    return { summary: "TCP truncated", layers, sport: 0, dport: 0, proto: "TCP" };
  }
  const sport = (payload[0] << 8) | payload[1];
  const dport = (payload[2] << 8) | payload[3];
  const seq = readU32(payload, 4);
  const ack = readU32(payload, 8);
  const dataOff = ((payload[12] >> 4) & 0x0f) * 4;
  const flags = payload[13];
  const win = (payload[14] << 8) | payload[15];
  const flagStr = tcpFlags(flags);
  layers.push({
    id: "tcp",
    name: "L4 TCP",
    summary: `${sport} → ${dport}  ${flagStr} seq=${seq} ack=${ack} win=${win}`,
    start: absOff,
    end: absOff + dataOff,
    color: "var(--c-l4)",
  });

  const data = payload.subarray(dataOff);
  let proto = "TCP";
  let summary = flagStr || "TCP";
  if (data.length) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
    if (looksHTTP(text)) {
      const http = decodeHTTP(data, absOff + dataOff, text);
      layers.push(...http.layers);
      summary = http.summary;
      proto = "HTTP";
    } else {
      layers.push({
        id: "tcp-pay",
        name: "payload",
        summary: asciiPreview(data, 48),
        start: absOff + dataOff,
        end: absOff + payload.length,
        color: "var(--c-pay)",
      });
      summary = `${flagStr} +${data.length}B`;
    }
  }
  return { summary, layers, sport, dport, proto };
}

function decodeHTTP(data, absOff, text) {
  const layers = [];
  const sep = text.indexOf("\r\n\r\n");
  if (sep < 0) {
    const line = text.split("\r\n")[0] || text.slice(0, 72);
    layers.push({
      id: "http",
      name: "L7 HTTP",
      summary: `(incomplete) ${line}`,
      start: absOff,
      end: absOff + data.length,
      color: "var(--c-l7)",
    });
    return { summary: `HTTP ${line}`, layers };
  }
  const head = text.slice(0, sep);
  const lines = head.split("\r\n");
  const startLine = lines[0] || "";
  const hdrBytes = sep + 4;
  layers.push({
    id: "http",
    name: "L7 HTTP",
    summary: startLine,
    detail: lines.slice(1).filter(Boolean).join("\n"),
    start: absOff,
    end: absOff + hdrBytes,
    color: "var(--c-l7)",
  });
  if (data.length > hdrBytes) {
    const body = data.subarray(hdrBytes);
    layers.push({
      id: "http-body",
      name: "body",
      summary: asciiPreview(body, 64),
      start: absOff + hdrBytes,
      end: absOff + data.length,
      color: "var(--c-pay)",
    });
  }
  return { summary: startLine, layers };
}

function looksHTTP(s) {
  return (
    s.startsWith("HTTP/") ||
    /^(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) /.test(s)
  );
}

function mac(b, o) {
  return [...b.subarray(o, o + 6)].map((x) => x.toString(16).padStart(2, "0")).join(":");
}
function ipv4(b, o) {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}
function readU32(b, o) {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
function etherName(t) {
  if (t === 0x0800) return "IPv4";
  if (t === 0x0806) return "ARP";
  if (t === 0x86dd) return "IPv6";
  return `0x${t.toString(16).padStart(4, "0")}`;
}
function protoName(p) {
  if (p === 1) return "ICMP";
  if (p === 6) return "TCP";
  if (p === 17) return "UDP";
  return String(p);
}
function tcpFlags(f) {
  const names = [];
  if (f & 0x01) names.push("FIN");
  if (f & 0x02) names.push("SYN");
  if (f & 0x04) names.push("RST");
  if (f & 0x08) names.push("PSH");
  if (f & 0x10) names.push("ACK");
  return names.join(",") || "-";
}
function asciiPreview(b, n) {
  let s = "";
  const lim = Math.min(b.length, n);
  for (let i = 0; i < lim; i++) {
    const c = b[i];
    s += c >= 0x20 && c <= 0x7e ? String.fromCharCode(c) : ".";
  }
  if (b.length > n) s += "…";
  return JSON.stringify(s);
}
