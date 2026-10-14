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


/** An app running on a simulated device: what it contacts and how it identifies itself. */
interface AppProfile { name: string; ua: string; quic: boolean; sites: [string, string][]; http?: [string, string][] }
const CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
const APPS: Record<string, AppProfile> = {
  chrome: { name: "Google Chrome", ua: CHROME_UA, quic: true,
    sites: [["www.google.com", "142.250.74.36"], ["fonts.gstatic.com", "142.250.185.67"], ["github.com", "140.82.121.4"], ["cdn.jsdelivr.net", "151.101.1.229"]],
    http: [["connectivitycheck.gstatic.com", "/generate_204"], ["neverssl.com", "/online/"], ["example.com", "/products/shoes?color=red"], ["news.example.org", "/world/2026/10/14/story.html"]] },
  edge: { name: "Microsoft Edge", ua: CHROME_UA + " Edg/129.0.0.0", quic: true,
    sites: [["www.bing.com", "13.107.21.200"], ["chatgpt.com", "104.18.32.47"]],
    http: [["www.msftconnecttest.com", "/connecttest.txt"], ["example.com", "/login?next=/account"]] },
  safari: { name: "Safari", ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1", quic: true,
    sites: [["www.apple.com", "17.253.144.10"], ["en.wikipedia.org", "185.15.59.224"]],
    http: [["captive.apple.com", "/hotspot-detect.html"], ["en.wikipedia.org", "/wiki/Packet_analyzer"]] },
  whatsapp: { name: "WhatsApp", ua: "WhatsApp/2.24.20 i", quic: false, sites: [["g.whatsapp.net", "157.240.22.53"], ["media.whatsapp.net", "157.240.22.60"]] },
  instagram: { name: "Instagram", ua: "Instagram 350.0 (iPhone)", quic: true, sites: [["i.instagram.com", "157.240.22.174"], ["scontent.cdninstagram.com", "157.240.22.63"]] },
  spotify: { name: "Spotify", ua: "Spotify/8.9.80 iOS", quic: false, sites: [["api.spotify.com", "35.186.224.25"], ["audio-ak.scdn.co", "151.101.2.248"]] },
  youtube: { name: "YouTube", ua: "com.google.android.youtube/19.40", quic: true, sites: [["www.youtube.com", "142.250.185.78"], ["rr3.googlevideo.com", "173.194.55.8"], ["i.ytimg.com", "142.250.185.86"]] },
  netflix: { name: "Netflix", ua: "Netflix/8.120 Cast", quic: false, sites: [["netflix.com", "54.155.178.5"], ["ipv4-c001.nflxvideo.net", "45.57.40.1"]] },
  steam: { name: "Steam", ua: "Valve/Steam HTTP Client 1.0", quic: false, sites: [["store.steampowered.com", "23.45.150.12"]], http: [["cdn.steamcontent.com", "/depot/228980/chunk/9f1c"]] },
  winupdate: { name: "Windows Update", ua: "Microsoft-Delivery-Optimization/10.0", quic: false, sites: [["fe3.delivery.mp.microsoft.com", "13.107.4.50"]], http: [["dl.windowsupdate.com", "/d/msdownload/update/kb5044284.cab"]] },
  vscode: { name: "VS Code", ua: "VSCode/1.94.0", quic: false, sites: [["marketplace.visualstudio.com", "13.107.42.18"], ["api.github.com", "140.82.121.6"]] },
  agent: { name: "NetScope agent", ua: "NetScopeSim/1.0", quic: false, sites: [], http: [["192.168.1.31", "/api/v1/status"], ["192.168.1.31", "/metrics"]] },
  thermo: { name: "Smart home device", ua: "ESP32-HTTPClient", quic: false, sites: [["mqtt.thermo.io", "3.120.45.10"]], http: [["mqtt.thermo.io", "/api/v1/telemetry"]] },
};
const DEVICE_APPS: Record<string, string[]> = {
  "192.168.1.14": ["chrome", "safari", "spotify", "vscode"],
  "192.168.1.22": ["whatsapp", "instagram", "safari", "spotify"],
  "192.168.1.31": ["agent"],
  "192.168.1.40": ["youtube", "netflix"],
  "192.168.1.57": ["chrome", "edge", "steam", "winupdate"],
  "192.168.1.63": ["thermo"],
};
const REASON: Record<number, string> = { 200: "OK", 204: "No Content", 301: "Moved Permanently", 304: "Not Modified", 404: "Not Found" };

function* dns(dev: SimDevice, site: string, ip: string) {
  const sp = 49152 + rnd(16000), id = rnd(65535);
  const q = [...be16(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(site), 0, 1, 0, 1];
  yield [frame(dev.mac, GW.mac, dev.ip, GW.ip, 17, udp(sp, 53, q))];
  const resp = [...be16(id), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...qname(site), 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, ...be32(60 + rnd(3000)), 0, 4, ...ipb(ip)];
  yield [frame(GW.mac, dev.mac, GW.ip, dev.ip, 17, udp(53, sp, resp))];
}
function* quic(dev: SimDevice, ip: string) {
  const sp = 49152 + rnd(16000);
  // QUIC long-header Initial packet (0xc3), version 1
  yield [frame(dev.mac, GW.mac, dev.ip, ip, 17, udp(sp, 443, [0xc3, 0, 0, 0, 1, ...Array.from({ length: 120 + rnd(1000) }, () => rnd(256))]))];
  yield [frame(GW.mac, dev.mac, ip, dev.ip, 17, udp(443, sp, Array.from({ length: 60 + rnd(1200) }, () => rnd(256))))];
}
function* tls(dev: SimDevice, site: string, ip: string) {
  const sp = 49152 + rnd(16000);
  let seq = rnd(2 ** 31), sseq = rnd(2 ** 31);
  yield [frame(dev.mac, GW.mac, dev.ip, ip, 6, tcp(sp, 443, seq, 0, 0x02))];
  yield [frame(GW.mac, dev.mac, ip, dev.ip, 6, tcp(443, sp, sseq, seq + 1, 0x12))];
  seq++; sseq++;
  const ch = clientHello(site);
  yield [frame(dev.mac, GW.mac, dev.ip, ip, 6, tcp(sp, 443, seq, sseq, 0x18, ch))];
  if (Math.random() < 0.1) yield [frame(dev.mac, GW.mac, dev.ip, ip, 6, tcp(sp, 443, seq, sseq, 0x18, ch))];
  seq += ch.length;
  const sh = serverHello();
  yield [frame(GW.mac, dev.mac, ip, dev.ip, 6, tcp(443, sp, sseq, seq, 0x18, sh)), frame(GW.mac, dev.mac, ip, dev.ip, 6, tcp(443, sp, sseq + sh.length, seq, 0x18, certificate(site)))];
  for (let i = 0; i < 1 + rnd(3); i++) {
    const pl = [0x17, 3, 3, ...be16(200 + rnd(1200)), ...Array.from({ length: 64 }, () => rnd(256))];
    yield [frame(GW.mac, dev.mac, ip, dev.ip, 6, tcp(443, sp, sseq, seq, 0x18, pl))];
  }
}
function* http(dev: SimDevice, app: AppProfile, host: string, path: string) {
  const sp = 49152 + rnd(16000);
  const dst = /^\d/.test(host) ? host : `93.184.${rnd(255)}.${1 + rnd(250)}`;
  const method = path.includes("telemetry") || path.includes("login") ? "POST" : "GET";
  const req = enc.encode(`${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${app.ua}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n`);
  yield [frame(dev.mac, GW.mac, dev.ip, dst, 6, tcp(sp, 80, rnd(2 ** 31), rnd(2 ** 31), 0x18, [...req]))];
  const status = path === "/generate_204" ? 204 : pick([200, 200, 200, 301, 304, 404]);
  const ct = path.endsWith(".png") ? "image/png" : path.includes(".html") || path.endsWith("/") ? "text/html" : path.endsWith(".cab") ? "application/vnd.ms-cab-compressed" : "application/json";
  const res = enc.encode(`HTTP/1.1 ${status} ${REASON[status]}\r\nContent-Type: ${ct}\r\nContent-Length: ${rnd(4000)}\r\nServer: nginx\r\n\r\n`);
  yield [frame(GW.mac, dev.mac, dst, dev.ip, 6, tcp(80, sp, rnd(2 ** 31), rnd(2 ** 31), 0x18, [...res]))];
}

/** One app session: DNS lookup → QUIC (UDP) → TLS with SNI → plain HTTP requests with User-Agent. */
function* session(dev: SimDevice, app: AppProfile, launch: boolean) {
  const sites = launch ? app.sites : app.sites.length ? [pick(app.sites)] : [];
  for (const [site, ip] of sites) {
    yield* dns(dev, site, ip);
    if (app.quic && Math.random() < 0.6) yield* quic(dev, ip);
    else yield* tls(dev, site, ip);
  }
  for (const [host, path] of app.http ?? []) if (launch || Math.random() < 0.5) yield* http(dev, app, host, path);
}

export function* scenario(): Generator<Uint8Array[]> {
  const launched = new Set<string>();
  while (true) {
    const dev = pick(SIM_DEVICES.slice(1));
    const key = pick(DEVICE_APPS[dev.ip]);
    const id = `${dev.ip}/${key}`;
    if (Math.random() < 0.06) {
      const t = pick(SIM_DEVICES);
      const arp = [0, 1, 8, 0, 6, 4, 0, 1, ...macb(dev.mac), ...ipb(dev.ip), 0, 0, 0, 0, 0, 0, ...ipb(t.ip)];
      yield [new Uint8Array([255, 255, 255, 255, 255, 255, ...macb(dev.mac), 8, 6, ...arp])];
      continue;
    }
    yield* session(dev, APPS[key], !launched.has(id));
    launched.add(id);
  }
}
