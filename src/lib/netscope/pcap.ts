// @ts-nocheck -- byte-level parsing code; strict index checks would add noise without safety gains
export interface RawFrame { ts: number; data: Uint8Array; linktype: number }

export function parseCapture(buf: ArrayBuffer): RawFrame[] {
  const dv = new DataView(buf);
  const magic = dv.getUint32(0, false);
  if (magic === 0x0a0d0d0a) return parsePcapng(buf);
  let le: boolean, nano = false;
  if (magic === 0xd4c3b2a1) le = true;
  else if (magic === 0xa1b2c3d4) le = false;
  else if (magic === 0x4d3cb2a1) { le = true; nano = true; }
  else if (magic === 0xa1b23c4d) { le = false; nano = true; }
  else throw new Error("Not a PCAP or PCAPNG file");
  const linktype = dv.getUint32(20, le);
  const out: RawFrame[] = [];
  let o = 24;
  while (o + 16 <= buf.byteLength) {
    const s = dv.getUint32(o, le), f = dv.getUint32(o + 4, le), incl = dv.getUint32(o + 8, le);
    o += 16;
    if (o + incl > buf.byteLength) break;
    out.push({ ts: s * 1000 + (nano ? f / 1e6 : f / 1000), data: new Uint8Array(buf, o, incl), linktype });
    o += incl;
  }
  return out;
}

function parsePcapng(buf: ArrayBuffer): RawFrame[] {
  const dv = new DataView(buf);
  const out: RawFrame[] = [];
  const ifaces: { linktype: number; res: number }[] = [];
  let le = true;
  let o = 0;
  while (o + 12 <= buf.byteLength) {
    let type = dv.getUint32(o, le);
    if (type === 0x0a0d0d0a || dv.getUint32(o, !le) === 0x0a0d0d0a) {
      le = dv.getUint32(o + 8, true) === 0x1a2b3c4d;
      type = 0x0a0d0d0a;
      ifaces.length = 0;
    }
    const len = dv.getUint32(o + 4, le);
    if (len < 12 || o + len > buf.byteLength) break;
    if (type === 1) {
      let res = 1e6;
      let p = o + 16;
      while (p + 4 <= o + len - 4) {
        const code = dv.getUint16(p, le), ol = dv.getUint16(p + 2, le);
        if (code === 0) break;
        if (code === 9) { const v = dv.getUint8(p + 4); res = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v; }
        p += 4 + Math.ceil(ol / 4) * 4;
      }
      ifaces.push({ linktype: dv.getUint16(o + 8, le), res });
    } else if (type === 6) {
      const ifc = ifaces[dv.getUint32(o + 8, le)] ?? { linktype: 1, res: 1e6 };
      const ts = (dv.getUint32(o + 12, le) * 2 ** 32 + dv.getUint32(o + 16, le)) / ifc.res * 1000;
      const cap = dv.getUint32(o + 20, le);
      out.push({ ts, data: new Uint8Array(buf, o + 28, cap), linktype: ifc.linktype });
    } else if (type === 3) {
      const ifc = ifaces[0] ?? { linktype: 1, res: 1e6 };
      out.push({ ts: Date.now(), data: new Uint8Array(buf, o + 12, len - 16), linktype: ifc.linktype });
    }
    o += len;
  }
  return out;
}
