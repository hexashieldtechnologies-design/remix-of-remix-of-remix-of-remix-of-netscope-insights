// @ts-nocheck -- shares the loose byte-parsing types of the decoder
import type { Packet } from "./decode";

/** Domain → application/service. First match wins. */
const SERVICES: [RegExp, string, string][] = [
  [/(^|\.)(youtube\.com|googlevideo\.com|ytimg\.com|youtu\.be)$/, "YouTube", "Video"],
  [/(^|\.)(whatsapp\.net|whatsapp\.com)$/, "WhatsApp", "Messaging"],
  [/(^|\.)(instagram\.com|cdninstagram\.com)$/, "Instagram", "Social"],
  [/(^|\.)(facebook\.com|fbcdn\.net)$/, "Facebook", "Social"],
  [/(^|\.)(spotify\.com|scdn\.co)$/, "Spotify", "Music"],
  [/(^|\.)(netflix\.com|nflxvideo\.net)$/, "Netflix", "Video"],
  [/(^|\.)(openai\.com|chatgpt\.com)$/, "ChatGPT", "AI"],
  [/(^|\.)(github\.com|githubusercontent\.com)$/, "GitHub", "Developer"],
  [/(^|\.)(telegram\.org|t\.me)$/, "Telegram", "Messaging"],
  [/(^|\.)(steamcommunity\.com|steampowered\.com|steamcontent\.com)$/, "Steam", "Gaming"],
  [/(^|\.)(icloud\.com|apple\.com|mzstatic\.com)$/, "Apple services", "System"],
  [/(^|\.)(windowsupdate\.com|microsoft\.com|msftconnecttest\.com)$/, "Windows Update", "System"],
  [/(^|\.)(gstatic\.com|googleapis\.com|google\.com|doubleclick\.net)$/, "Google Chrome", "Browser"],
  [/(^|\.)(jsdelivr\.net|cloudflare\.com|akamaized\.net|fastly\.net)$/, "Web content (CDN)", "Browser"],
  [/(^|\.)(thermo\.io|tuya\.com|shelly\.cloud)$/, "Smart home device", "IoT"],
];

/** HTTP User-Agent → application. First match wins. */
const AGENTS: [RegExp, string, string][] = [
  [/Edg\//, "Microsoft Edge", "Browser"],
  [/OPR\/|Opera/, "Opera", "Browser"],
  [/Firefox\//, "Mozilla Firefox", "Browser"],
  [/Chrome\//, "Google Chrome", "Browser"],
  [/Version\/.*Safari/, "Safari", "Browser"],
  [/WhatsApp/, "WhatsApp", "Messaging"],
  [/Spotify/, "Spotify", "Music"],
  [/Instagram/, "Instagram", "Social"],
  [/Steam/, "Steam", "Gaming"],
  [/Microsoft-Delivery-Optimization|Windows-Update|WindowsPowerShell/, "Windows Update", "System"],
  [/VSCode|Code\//, "VS Code", "Developer"],
  [/curl|Wget|python-requests/, "Command line tool", "Developer"],
  [/NetScopeSim/, "NetScope agent", "Developer"],
  [/ESP32|MQTT|Mosquitto/, "Smart home device", "IoT"],
];

/** Well-known ports → background/system service. */
const PORTS: Record<number, [string, string]> = {
  53: ["Name lookup (DNS)", "System"],
  67: ["Network setup (DHCP)", "System"],
  68: ["Network setup (DHCP)", "System"],
  123: ["Clock sync (NTP)", "System"],
  137: ["Windows networking", "System"],
  138: ["Windows networking", "System"],
  445: ["File sharing (SMB)", "System"],
  1883: ["Smart home device", "IoT"],
  1900: ["Device discovery (SSDP)", "System"],
  5353: ["Device discovery (mDNS)", "System"],
  5228: ["Android push (Google)", "System"],
  22: ["SSH session", "Developer"],
  3389: ["Remote desktop", "System"],
  8883: ["Smart home device", "IoT"],
};

function byDomain(d?: string): [string, string] | null {
  if (!d) return null;
  const low = d.toLowerCase();
  for (const [re, name, cat] of SERVICES) if (re.test(low)) return [name, cat];
  return null;
}

function byAgent(ua?: string): [string, string] | null {
  if (!ua) return null;
  for (const [re, name, cat] of AGENTS) if (re.test(ua)) return [name, cat];
  return null;
}

/**
 * Attach the application, the service domain and the full URL to a decoded packet.
 * `resolve` maps an IP back to a hostname learned from DNS answers / TLS SNI.
 */
export function annotate(p: Packet, resolve: (ip: string) => string | undefined): Packet {
  const domain =
    p.http?.host ?? p.tls?.sni ?? p.tls?.cert ?? p.dns?.name ?? resolve(p.dst) ?? resolve(p.src);
  p.domain = domain;

  if (p.http?.method) p.url = `http://${p.http.host ?? p.dst}${p.http.path ?? "/"}`;
  else if (p.tls?.sni) p.url = `https://${p.tls.sni}`;
  else if (p.dns && !p.dns.response) p.url = `dns://${p.dns.name}`;
  else if (domain && (p.dstPort === 443 || p.srcPort === 443)) p.url = `https://${domain}`;
  else if (domain) p.url = domain;

  const quic = p.proto === "UDP" && (p.dstPort === 443 || p.srcPort === 443);
  const hit =
    byAgent(p.http?.ua) ??
    byDomain(domain) ??
    (quic ? ["Browser / QUIC app", "Browser"] : null) ??
    PORTS[p.dstPort!] ??
    PORTS[p.srcPort!] ??
    (p.proto === "ARP" ? ["Local network (ARP)", "System"] : null) ??
    (p.proto === "ICMP" ? ["Ping / diagnostics", "System"] : null) ??
    (p.dstPort === 80 || p.srcPort === 80 ? ["Web browsing (HTTP)", "Browser"] : null) ??
    ["Unidentified traffic", "Other"];

  p.app = hit[0];
  p.appCat = hit[1];

  // What the user actually did, in plain words.
  if (p.http?.method) p.action = `${p.http.method} ${p.url}`;
  else if (p.tls?.type === "ClientHello") p.action = `Opening secure connection to ${p.tls.sni ?? p.dst}`;
  else if (p.tls?.type === "Certificate") p.action = `Server certificate ${p.tls.cert ?? ""}`;
  else if (p.dns) p.action = p.dns.response ? `Resolved ${p.dns.name}` : `Looking up ${p.dns.name}`;
  else if (quic) p.action = `Encrypted QUIC traffic${domain ? ` with ${domain}` : ""}`;
  else if (p.proto === "ARP") p.action = p.info;
  else p.action = p.info;

  return p;
}

export const CAT_CLS: Record<string, string> = {
  Browser: "text-p-http",
  Video: "text-p-tls",
  Messaging: "text-p-dns",
  Social: "text-p-dns",
  Music: "text-p-udp",
  AI: "text-p-tls",
  Developer: "text-p-tcp",
  Gaming: "text-p-udp",
  System: "text-muted-foreground",
  IoT: "text-p-arp",
  Other: "text-muted-foreground",
};
