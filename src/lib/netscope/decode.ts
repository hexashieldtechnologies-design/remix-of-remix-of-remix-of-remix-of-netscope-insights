export type Proto = "DNS" | "TLS" | "HTTP" | "TCP" | "UDP" | "ICMP" | "ARP" | "IPv6" | "OTHER";

export interface Field {
  k: string;
  v: string;
  /** byte range within frame for hex highlighting */
  r?: [number, number];
}
export interface Layer {
  name: string;
  fields: Field[];
  r?: [number, number];
}

export interface Packet {
  id: number;
  ts: number; // ms epoch
  src: string;
  dst: string;
  srcMac?: string;
  dstMac?: string;
  srcPort?: number;
  dstPort?: number;
  proto: Proto;
  length: number;
  info: string;
  layers: Layer[];
  bytes: Uint8Array;
  tcpFlags?: string;
  tcpSeq?: number;
  payloadLen?: number;
  retrans?: boolean;
  dns?: { id: number; response: boolean; name: string; qtype: string; answers: string[]; latencyMs?: number };
  tls?: { type: string; sni?: string; version?: string; ciphers?: string[]; cipher?: string; cert?: string };
  http?: { method?: string; path?: string; host?: string; status?: number; contentType?: string; version: string };
}

const hex2 = (n: number) => n.toString(16).padStart(2, "0");
export const mac = (b: Uint8Array, o: number) => Array.from(b.slice(o, o + 6), hex2).join(":");
const ip4 = (b: Uint8Array, o: number) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];
const u32 = (b: Uint8Array, o: number) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const ip6 = (b: Uint8Array, o: number) => {
  const p: string[] = [];
  for (let i = 0; i < 16; i += 2) p.push(u16(b, o + i).toString(16));
  return p.join(":").replace(/(^|:)0(:0)+(:|$)/, "::");
};

export const QTYPES: Record<number, string> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY" };
export const CIPHERS: Record<number, string> = {
  0x1301: "TLS_AES_128_GCM_SHA256",
  0x1302: "TLS_AES_256_GCM_SHA384",
  0x1303: "TLS_CHACHA20_POLY1305_SHA256",
  0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
  0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
  0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
  0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
};
const TLSV: Record<number, string> = { 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3" };

function dnsName(b: Uint8Array, o: number, base: number): [string, number] {
  const labels: string[] = [];
  let jumped = false;
  let end = o;
  let guard = 0;
  while (o < b.length && guard++ < 64) {
    const len = b[o];
    if (len === 0) { o++; break; }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | b[o + 1];
      if (!jumped) end = o + 2;
      jumped = true;
      o = base + ptr;
      continue;
    }
    labels.push(new TextDecoder().decode(b.slice(o + 1, o + 1 + len)));
    o += len + 1;
  }
  return [labels.join(".") || "<root>", jumped ? end : o];
}

function decodeDNS(b: Uint8Array, o: number, p: Packet) {
  if (b.length - o < 12) return;
  const id = u16(b, o), flags = u16(b, o + 2), qd = u16(b, o + 4), an = u16(b, o + 6);
  const response = !!(flags & 0x8000);
  const rcode = flags & 0xf;
  let off = o + 12;
  let name = "", qtype = "";
  const fields: Field[] = [
    { k: "Transaction ID", v: "0x" + id.toString(16).padStart(4, "0"), r: [o, o + 2] },
    { k: "Type", v: response ? `Response (rcode ${rcode === 0 ? "NOERROR" : rcode === 3 ? "NXDOMAIN" : rcode})` : "Standard query", r: [o + 2, o + 4] },
    { k: "Questions / Answers", v: `${qd} / ${an}`, r: [o + 4, o + 8] },
  ];
  try {
    for (let i = 0; i < qd; i++) {
      const s = off;
      [name, off] = dnsName(b, off, o);
      qtype = QTYPES[u16(b, off)] ?? String(u16(b, off));
      off += 4;
      fields.push({ k: "Query", v: `${name} ${qtype}`, r: [s, off] });
    }
    const answers: string[] = [];
    for (let i = 0; i < an && off < b.length; i++) {
      const s = off;
      let n: string;
      [n, off] = dnsName(b, off, o);
      const t = u16(b, off), ttl = u32(b, off + 4), rl = u16(b, off + 8);
      off += 10;
      let val = "";
      if (t === 1 && rl === 4) val = ip4(b, off);
      else if (t === 28 && rl === 16) val = ip6(b, off);
      else if (t === 5 || t === 12 || t === 2) val = dnsName(b, off, o)[0];
      else val = `${rl} bytes`;
      off += rl;
      const ans = `${QTYPES[t] ?? t} ${val}`;
      answers.push(ans);
      fields.push({ k: "Answer", v: `${n} ${ans} (ttl ${ttl}s)`, r: [s, off] });
    }
    p.dns = { id, response, name, qtype, answers };
  } catch {
    /* truncated */
  }
  p.proto = "DNS";
  p.info = response ? `Response ${qtype} ${name} → ${p.dns?.answers.join(", ") || (rcode === 3 ? "NXDOMAIN" : "—")}` : `Query ${qtype} ${name}`;
  p.layers.push({ name: "Domain Name System", fields, r: [o, b.length] });
}

function decodeTLS(b: Uint8Array, o: number, p: Packet): boolean {
  const ct = b[o];
  if (![0x14, 0x15, 0x16, 0x17].includes(ct) || b[o + 1] !== 3 || o + 5 > b.length) return false;
  const rv = TLSV[u16(b, o + 1)] ?? "?";
  const rlen = u16(b, o + 3);
  const fields: Field[] = [
    { k: "Content Type", v: ({ 0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data" } as Record<number, string>)[ct], r: [o, o + 1] },
    { k: "Record Version", v: rv, r: [o + 1, o + 3] },
    { k: "Length", v: String(rlen), r: [o + 3, o + 5] },
  ];
  p.proto = "TLS";
  p.tls = { type: "Application Data", version: rv };
  p.info = `Application Data (${rlen} bytes, encrypted)`;
  if (ct === 0x16 && o + 9 < b.length) {
    const ht = b[o + 5];
    let h = o + 9;
    const hv = TLSV[u16(b, h)] ?? rv;
    h += 2 + 32;
    const sidLen = b[h];
    h += 1 + sidLen;
    if (ht === 1) {
      const csLen = u16(b, h);
      const ciphers: string[] = [];
      for (let i = 0; i < csLen; i += 2) ciphers.push(CIPHERS[u16(b, h + 2 + i)] ?? "0x" + u16(b, h + 2 + i).toString(16));
      fields.push({ k: "Handshake", v: "ClientHello", r: [o + 5, o + 6] });
      fields.push({ k: "Cipher Suites", v: `${ciphers.length} offered`, r: [h, h + 2 + csLen] });
      ciphers.forEach((c) => fields.push({ k: "  ·", v: c }));
      h += 2 + csLen;
      h += 1 + b[h];
      const extEnd = h + 2 + u16(b, h);
      h += 2;
      let sni: string | undefined;
      let version = hv;
      while (h + 4 <= extEnd && h + 4 <= b.length) {
        const et = u16(b, h), el = u16(b, h + 2);
        if (et === 0 && el > 5) {
          const nl = u16(b, h + 7);
          sni = new TextDecoder().decode(b.slice(h + 9, h + 9 + nl));
          fields.push({ k: "Server Name (SNI)", v: sni, r: [h, h + 4 + el] });
        }
        if (et === 43) version = "TLS 1.3";
        h += 4 + el;
      }
      p.tls = { type: "ClientHello", sni, version, ciphers };
      p.info = `Client Hello${sni ? ` · SNI=${sni}` : ""}`;
    } else if (ht === 2) {
      const cs = CIPHERS[u16(b, h)] ?? "0x" + u16(b, h).toString(16);
      fields.push({ k: "Handshake", v: "ServerHello", r: [o + 5, o + 6] }, { k: "Selected Cipher", v: cs, r: [h, h + 2] });
      p.tls = { type: "ServerHello", cipher: cs, version: hv };
      p.info = `Server Hello · ${cs}`;
    } else if (ht === 11) {
      const txt = new TextDecoder("latin1").decode(b.slice(h, b.length));
      const cn = txt.match(/CN=([\w.*-]+)/)?.[1];
      fields.push({ k: "Handshake", v: "Certificate" }, { k: "Subject CN", v: cn ?? "(unparsed)" });
      p.tls = { type: "Certificate", cert: cn, version: rv };
      p.info = `Certificate${cn ? ` · CN=${cn}` : ""}`;
    } else {
      p.tls = { type: `Handshake(${ht})`, version: rv };
      p.info = `Handshake type ${ht}`;
    }
  }
  p.layers.push({ name: `Transport Layer Security (${p.tls.version})`, fields, r: [o, Math.min(b.length, o + 5 + rlen)] });
  return true;
}

const METHODS = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) (\S+) (HTTP\/[\d.]+)/;
function decodeHTTP(b: Uint8Array, o: number, p: Packet): boolean {
  if (b.length - o >= 24 && new TextDecoder("latin1").decode(b.slice(o, o + 24)) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
    p.proto = "HTTP";
    p.http = { version: "HTTP/2" };
    p.info = "HTTP/2 connection preface";
    p.layers.push({ name: "HyperText Transfer Protocol 2", fields: [{ k: "Preface", v: "PRI * HTTP/2.0", r: [o, o + 24] }], r: [o, b.length] });
    return true;
  }
  const head = new TextDecoder("latin1").decode(b.slice(o, Math.min(b.length, o + 2048)));
  const first = head.split("\r\n")[0];
  const m = first.match(METHODS);
  const s = first.match(/^(HTTP\/[\d.]+) (\d{3}) ?(.*)/);
  if (!m && !s) return false;
  const headers = head.split("\r\n\r\n")[0].split("\r\n").slice(1);
  const hv = (n: string) => headers.find((h) => h.toLowerCase().startsWith(n + ":"))?.slice(n.length + 1).trim();
  p.proto = "HTTP";
  p.http = m
    ? { method: m[1], path: m[2], version: m[3], host: hv("host") }
    : { status: +s![2], version: s![1], contentType: hv("content-type") };
  p.info = m ? `${m[1]} ${m[2]}${p.http.host ? ` (${p.http.host})` : ""}` : `${s![2]} ${s![3]}${p.http.contentType ? ` · ${p.http.contentType}` : ""}`;
  p.layers.push({
    name: "HyperText Transfer Protocol",
    fields: [{ k: m ? "Request" : "Response", v: first, r: [o, o + first.length] }, ...headers.map((h) => { const i = h.indexOf(":"); return { k: h.slice(0, i), v: h.slice(i + 1).trim() }; })],
    r: [o, b.length],
  });
  return true;
}

function decodeL4(b: Uint8Array, o: number, proto: number, p: Packet) {
  if (proto === 6 && o + 20 <= b.length) {
    const sp = u16(b, o), dp = u16(b, o + 2), seq = u32(b, o + 4), ack = u32(b, o + 8);
    const doff = (b[o + 12] >> 4) * 4, fl = b[o + 13];
    const names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"].filter((_, i) => fl & (1 << i));
    const pl = Math.max(0, b.length - o - doff);
    Object.assign(p, { srcPort: sp, dstPort: dp, proto: "TCP", tcpFlags: names.join(","), tcpSeq: seq, payloadLen: pl });
    p.info = `${sp} → ${dp} [${names.join(", ")}] Seq=${seq} Ack=${ack} Win=${u16(b, o + 14)} Len=${pl}`;
    p.layers.push({
      name: `Transmission Control Protocol, ${sp} → ${dp}`,
      r: [o, o + doff],
      fields: [
        { k: "Source Port", v: String(sp), r: [o, o + 2] },
        { k: "Destination Port", v: String(dp), r: [o + 2, o + 4] },
        { k: "Sequence Number", v: String(seq), r: [o + 4, o + 8] },
        { k: "Ack Number", v: String(ack), r: [o + 8, o + 12] },
        { k: "Header Length", v: `${doff} bytes`, r: [o + 12, o + 13] },
        { k: "Flags", v: `0x${hex2(fl)} (${names.join(", ")})`, r: [o + 13, o + 14] },
        { k: "Window", v: String(u16(b, o + 14)), r: [o + 14, o + 16] },
        { k: "Payload", v: `${pl} bytes` },
      ],
    });
    const po = o + doff;
    if (pl > 0) {
      if (decodeTLS(b, po, p)) return;
      decodeHTTP(b, po, p);
    }
  } else if (proto === 17 && o + 8 <= b.length) {
    const sp = u16(b, o), dp = u16(b, o + 2), len = u16(b, o + 4);
    Object.assign(p, { srcPort: sp, dstPort: dp, proto: "UDP", payloadLen: len - 8 });
    p.info = `${sp} → ${dp} Len=${len - 8}`;
    p.layers.push({
      name: `User Datagram Protocol, ${sp} → ${dp}`,
      r: [o, o + 8],
      fields: [
        { k: "Source Port", v: String(sp), r: [o, o + 2] },
        { k: "Destination Port", v: String(dp), r: [o + 2, o + 4] },
        { k: "Length", v: String(len), r: [o + 4, o + 6] },
        { k: "Checksum", v: "0x" + u16(b, o + 6).toString(16), r: [o + 6, o + 8] },
      ],
    });
    if (sp === 53 || dp === 53 || sp === 5353 || dp === 5353) decodeDNS(b, o + 8, p);
    else if (sp === 443 || dp === 443) { p.info = `QUIC ${sp} → ${dp} Len=${len - 8} (encrypted)`; }
  } else if ((proto === 1 || proto === 58) && o + 4 <= b.length) {
    const t = b[o];
    p.proto = "ICMP";
    p.info = ({ 0: "Echo reply", 8: "Echo request", 3: "Destination unreachable", 11: "Time exceeded", 128: "Echo request", 129: "Echo reply" } as Record<number, string>)[t] ?? `Type ${t}`;
    p.layers.push({ name: "Internet Control Message Protocol", r: [o, b.length], fields: [{ k: "Type", v: `${t} (${p.info})`, r: [o, o + 1] }, { k: "Code", v: String(b[o + 1]), r: [o + 1, o + 2] }] });
  }
}

function decodeIP(b: Uint8Array, o: number, p: Packet) {
  const v = b[o] >> 4;
  if (v === 4) {
    const ihl = (b[o] & 15) * 4, proto = b[o + 9];
    p.src = ip4(b, o + 12);
    p.dst = ip4(b, o + 16);
    p.layers.push({
      name: `Internet Protocol Version 4, ${p.src} → ${p.dst}`,
      r: [o, o + ihl],
      fields: [
        { k: "Header Length", v: `${ihl} bytes`, r: [o, o + 1] },
        { k: "Total Length", v: String(u16(b, o + 2)), r: [o + 2, o + 4] },
        { k: "Identification", v: "0x" + u16(b, o + 4).toString(16), r: [o + 4, o + 6] },
        { k: "TTL", v: String(b[o + 8]), r: [o + 8, o + 9] },
        { k: "Protocol", v: ({ 1: "ICMP", 6: "TCP", 17: "UDP" } as Record<number, string>)[proto] ?? String(proto), r: [o + 9, o + 10] },
        { k: "Source", v: p.src, r: [o + 12, o + 16] },
        { k: "Destination", v: p.dst, r: [o + 16, o + 20] },
      ],
    });
    decodeL4(b, o + ihl, proto, p);
  } else if (v === 6) {
    p.src = ip6(b, o + 8);
    p.dst = ip6(b, o + 24);
    p.proto = "IPv6";
    p.info = "IPv6";
    p.layers.push({ name: `Internet Protocol Version 6, ${p.src} → ${p.dst}`, r: [o, o + 40], fields: [{ k: "Next Header", v: String(b[o + 6]), r: [o + 6, o + 7] }, { k: "Hop Limit", v: String(b[o + 7]), r: [o + 7, o + 8] }, { k: "Source", v: p.src, r: [o + 8, o + 24] }, { k: "Destination", v: p.dst, r: [o + 24, o + 40] }] });
    decodeL4(b, o + 40, b[o + 6], p);
  }
}

/** linktype: 1 Ethernet, 101 raw IP, 113 Linux SLL */
export function decodeFrame(bytes: Uint8Array, ts: number, id: number, linktype = 1): Packet {
  const p: Packet = { id, ts, src: "?", dst: "?", proto: "OTHER", length: bytes.length, info: "", layers: [], bytes };
  p.layers.push({ name: `Frame ${id}: ${bytes.length} bytes captured`, fields: [{ k: "Arrival Time", v: new Date(ts).toISOString() }, { k: "Frame Length", v: `${bytes.length} bytes` }] });
  try {
    if (linktype === 101) decodeIP(bytes, 0, p);
    else if (linktype === 113) {
      const et = u16(bytes, 14);
      if (et === 0x0800 || et === 0x86dd) decodeIP(bytes, 16, p);
    } else {
      p.dstMac = mac(bytes, 0);
      p.srcMac = mac(bytes, 6);
      const et = u16(bytes, 12);
      p.layers.push({ name: `Ethernet II, ${p.srcMac} → ${p.dstMac}`, r: [0, 14], fields: [{ k: "Destination", v: p.dstMac, r: [0, 6] }, { k: "Source", v: p.srcMac, r: [6, 12] }, { k: "Type", v: "0x" + et.toString(16).padStart(4, "0"), r: [12, 14] }] });
      if (et === 0x0800 || et === 0x86dd) decodeIP(bytes, 14, p);
      else if (et === 0x0806) {
        const op = u16(bytes, 20);
        p.proto = "ARP";
        p.src = ip4(bytes, 28);
        p.dst = ip4(bytes, 38);
        p.info = op === 1 ? `Who has ${p.dst}? Tell ${p.src}` : `${p.src} is at ${mac(bytes, 22)}`;
        p.layers.push({ name: "Address Resolution Protocol", r: [14, 42], fields: [{ k: "Opcode", v: op === 1 ? "request" : "reply", r: [20, 22] }, { k: "Sender MAC", v: mac(bytes, 22), r: [22, 28] }, { k: "Sender IP", v: p.src, r: [28, 32] }, { k: "Target IP", v: p.dst, r: [38, 42] }] });
      }
    }
  } catch {
    p.info ||= "Malformed packet";
  }
  if (!p.info) p.info = `${p.proto} ${bytes.length} bytes`;
  return p;
}

/** Stateful pass: retransmissions + DNS latency */
export class Analyzer {
  seen = new Set<string>();
  dnsPending = new Map<string, number>();
  apply(p: Packet) {
    if (p.tcpSeq !== undefined && p.payloadLen) {
      const k = `${p.src}:${p.srcPort}>${p.dst}:${p.dstPort}#${p.tcpSeq}`;
      if (this.seen.has(k)) { p.retrans = true; p.info = "[TCP Retransmission] " + p.info; }
      else this.seen.add(k);
      if (this.seen.size > 50000) this.seen.clear();
    }
    if (p.dns) {
      const k = `${p.dns.id}-${p.dns.name}`;
      if (!p.dns.response) this.dnsPending.set(k, p.ts);
      else if (this.dnsPending.has(k)) {
        p.dns.latencyMs = p.ts - this.dnsPending.get(k)!;
        p.info += ` · ${p.dns.latencyMs.toFixed(1)} ms`;
        this.dnsPending.delete(k);
      }
    }
    return p;
  }
}
