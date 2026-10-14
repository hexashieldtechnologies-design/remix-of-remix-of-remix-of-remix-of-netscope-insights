// @ts-nocheck -- byte-level parsing code; strict index checks would add noise without safety gains
// Synthesizes real wire-format Ethernet frames so the simulator exercises the same decoder as PCAP files.
export interface SimDevice { ip: string; mac: string; host: string; vendor: string }

export const SIM_DEVICES: SimDevice[] = [
  { ip: "192.168.1.1", mac: "f4:f2:6d:11:22:01", host: "gateway.lan", vendor: "TP-Link" },
  { ip: "192.168.1.14", mac: "3c:22:fb:a1:5e:14", host: "macbook-pro", vendor: "Apple" },
  { ip: "192.168.1.22", mac: "a4:83:e7:0c:9d:22", host: "iphone-maya", vendor: "Apple" },
  { ip: "192.168.1.31", mac: "b8:27:eb:44:10:31", host: "raspberrypi", vendor: "Raspberry Pi" },
  { ip: "192.168.1.40", mac: "00:1a:11:7f:20:40", host: "chromecast", vendor: "Google" },
  { ip: "192.168.1.57", mac: "d8:bb:c1:93:aa:57", host: "desktop-win11", vendor: "Micro-Star" },
  { ip: "192.168.1.63", mac: "50:02:91:3e:71:63", host: "esp32-thermostat", vendor: "Espressif" },
];
const GW = SIM_DEVICES[0];
const SITES: [string, string][] = [
  ["github.com", "140.82.121.4"], ["api.openai.com", "104.18.7.192"], ["www.google.com", "142.250.74.36"],
  ["fonts.gstatic.com", "142.250.185.67"], ["cdn.jsdelivr.net", "151.101.1.229"], ["netflix.com", "54.155.178.5"],
  ["mqtt.thermo.io", "3.120.45.10"], ["updates.microsoft.com", "13.107.4.50"], ["icloud.com", "17.253.144.10"],
];

const enc = new TextEncoder();
const ipb = (ip: string) => ip.split(".").map(Number);
const macb = (m: string) => m.split(":").map((h) => parseInt(h, 16));
const be16 = (n: number) => [(n >> 8) & 255, n & 255];
const be32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const rnd = (n: number) => Math.floor(Math.random() * n);
const pick = <T,>(a: T[]) => a[rnd(a.length)];

function frame(sMac: string, dMac: string, sIp: string, dIp: string, proto: number, l4: number[]) {
  const total = 20 + l4.length;
  const ip = [0x45, 0, ...be16(total), ...be16(rnd(65535)), 0x40, 0, 64, proto, 0, 0, ...ipb(sIp), ...ipb(dIp)];
  return new Uint8Array([...macb(dMac), ...macb(sMac), 0x08, 0x00, ...ip, ...l4]);
}
const udp = (sp: number, dp: number, pl: number[]) => [...be16(sp), ...be16(dp), ...be16(8 + pl.length), 0, 0, ...pl];
const tcp = (sp: number, dp: number, seq: number, ack: number, flags: number, pl: number[] = []) =>
  [...be16(sp), ...be16(dp), ...be32(seq), ...be32(ack), 0x50, flags, ...be16(64240), 0, 0, 0, 0, ...pl];
const qname = (n: string) => [...n.split(".").flatMap((l) => [l.length, ...enc.encode(l)]), 0];

function clientHello(sni: string) {
  const ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9];
  const name = [...enc.encode(sni)];
  const sniExt = [0, 0, ...be16(name.length + 5), ...be16(name.length + 3), 0, ...be16(name.length), ...name];
  const verExt = [0, 43, 0, 3, 2, 3, 4];
  const exts = [...sniExt, ...verExt];
  const body = [3, 3, ...Array.from({ length: 32 }, () => rnd(256)), 0, ...be16(ciphers.length * 2), ...ciphers.flatMap(be16), 1, 0, ...be16(exts.length), ...exts];
  const hs = [1, 0, ...be16(body.length), ...body];
  return [0x16, 3, 1, ...be16(hs.length), ...hs];
}
function serverHello() {
  const body = [3, 3, ...Array.from({ length: 32 }, () => rnd(256)), 0, ...be16(pick([0x1301, 0x1302, 0xc02f])), 0, 0, 0];
  const hs = [2, 0, ...be16(body.length), ...body];
  return [0x16, 3, 3, ...be16(hs.length), ...hs];
}
function certificate(cn: string) {
  const body = [0, 0, 0, ...enc.encode(`0\x82..CN=${cn}, O=Example Trust, C=US`)];
  const hs = [11, 0, ...be16(body.length), ...body];
  return [0x16, 3, 3, ...be16(hs.length), ...hs];
}

export function* scenario(): Generator<Uint8Array[]> {
  while (true) {
    const dev = pick(SIM_DEVICES.slice(1));
    const [site, sip] = pick(SITES);
    const sp = 49152 + rnd(16000);
    const r = Math.random();
    if (r < 0.3) {
      const id = rnd(65535), qt = Math.random() < 0.7 ? 1 : 28;
      const q = [...be16(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(site), ...be16(qt), 0, 1];
      yield [frame(dev.mac, GW.mac, dev.ip, GW.ip, 17, udp(sp, 53, q))];
      const rd = qt === 1 ? ipb(sip) : [0x2a, 0, 0x14, 0x50, ...Array(12).fill(0)];
      const resp = [...be16(id), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...qname(site), ...be16(qt), 0, 1, 0xc0, 12, ...be16(qt), 0, 1, ...be32(60 + rnd(3000)), ...be16(rd.length), ...rd];
      yield [frame(GW.mac, dev.mac, GW.ip, dev.ip, 17, udp(53, sp, resp))];
    } else if (r < 0.65) {
      let seq = rnd(2 ** 31), sseq = rnd(2 ** 31);
      yield [frame(dev.mac, GW.mac, dev.ip, sip, 6, tcp(sp, 443, seq, 0, 0x02))];
      yield [frame(GW.mac, dev.mac, sip, dev.ip, 6, tcp(443, sp, sseq, seq + 1, 0x12))];
      seq++; sseq++;
      const ch = clientHello(site);
      yield [frame(dev.mac, GW.mac, dev.ip, sip, 6, tcp(sp, 443, seq, sseq, 0x18, ch))];
      if (Math.random() < 0.15) yield [frame(dev.mac, GW.mac, dev.ip, sip, 6, tcp(sp, 443, seq, sseq, 0x18, ch))];
      seq += ch.length;
      const sh = serverHello();
      yield [frame(GW.mac, dev.mac, sip, dev.ip, 6, tcp(443, sp, sseq, seq, 0x18, sh)), frame(GW.mac, dev.mac, sip, dev.ip, 6, tcp(443, sp, sseq + sh.length, seq, 0x18, certificate(site)))];
      for (let i = 0; i < 2 + rnd(4); i++) {
        const app = [0x17, 3, 3, ...be16(200 + rnd(1200))];
        const pl = [...app, ...Array.from({ length: 64 }, () => rnd(256))];
        yield [frame(GW.mac, dev.mac, sip, dev.ip, 6, tcp(443, sp, sseq, seq, 0x18, pl))];
      }
    } else if (r < 0.85) {
      const host = dev.vendor === "Espressif" ? "mqtt.thermo.io" : pick(["192.168.1.31", "router.lan", "api.local"]);
      const dst = host.startsWith("192") ? host : dev === SIM_DEVICES[3] ? GW.ip : SIM_DEVICES[3].ip;
      const path = pick(["/api/v1/status", "/metrics", "/index.html", "/img/logo.png", "/api/v1/telemetry"]);
      const method = path.includes("telemetry") ? "POST" : "GET";
      const req = enc.encode(`${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: NetScopeSim/1.0\r\nAccept: */*\r\n\r\n`);
      yield [frame(dev.mac, GW.mac, dev.ip, dst, 6, tcp(sp, 80, rnd(2 ** 31), rnd(2 ** 31), 0x18, [...req]))];
      const status = pick([200, 200, 200, 304, 404, 500]);
      const ct = path.endsWith(".png") ? "image/png" : path.endsWith(".html") ? "text/html" : "application/json";
      const res = enc.encode(`HTTP/1.1 ${status} ${({ 200: "OK", 304: "Not Modified", 404: "Not Found", 500: "Internal Server Error" } as Record<number, string>)[status]}\r\nContent-Type: ${ct}\r\nContent-Length: ${rnd(4000)}\r\nServer: nginx\r\n\r\n`);
      yield [frame(GW.mac, dev.mac, dst, dev.ip, 6, tcp(80, sp, rnd(2 ** 31), rnd(2 ** 31), 0x18, [...res]))];
    } else if (r < 0.93) {
      yield [frame(dev.mac, GW.mac, dev.ip, sip, 17, udp(sp, 443, Array.from({ length: 80 + rnd(600) }, () => rnd(256))))];
    } else {
      const t = pick(SIM_DEVICES);
      const arp = [0, 1, 8, 0, 6, 4, 0, 1, ...macb(dev.mac), ...ipb(dev.ip), 0, 0, 0, 0, 0, 0, ...ipb(t.ip)];
      yield [new Uint8Array([255, 255, 255, 255, 255, 255, ...macb(dev.mac), 8, 6, ...arp])];
    }
  }
}
