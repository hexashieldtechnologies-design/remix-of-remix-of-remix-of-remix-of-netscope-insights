import type { Packet } from "./decode";

export interface Explanation { summary: string; points: string[]; warnings: string[] }

const PORTS: Record<number, string> = {
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP email", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "web (HTTP)",
  110: "POP3 email", 123: "time sync (NTP)", 143: "IMAP email", 443: "secure web (HTTPS)", 445: "Windows file sharing",
  1900: "device discovery (SSDP)", 3389: "Remote Desktop", 5353: "local name discovery (mDNS)", 8080: "web (alt HTTP)",
};
const PLAINTEXT = new Set([21, 23, 25, 80, 110, 143]);

/** Plain-language, rule-based explanation of a decoded packet. */
export function explainPacket(p: Packet, host: (ip: string) => string | undefined): Explanation {
  const who = (ip: string) => host(ip) ?? ip;
  const points: string[] = [];
  const warnings: string[] = [];
  let summary = `${who(p.src)} sent ${p.length} bytes to ${who(p.dst)} using ${p.proto}.`;

  if (p.app) points.push(`Likely app: ${p.app}${p.appCat ? ` (${p.appCat})` : ""}.`);
  if (p.dns) {
    summary = p.dns.response
      ? `DNS answer: "${p.dns.name}" resolves to ${p.dns.answers.join(", ") || "nothing (no records)"}.`
      : `DNS lookup: ${who(p.src)} is asking where "${p.dns.name}" (${p.dns.qtype}) lives — the next step is connecting to that site.`;
    if (p.dns.latencyMs != null) points.push(`DNS reply took ${p.dns.latencyMs.toFixed(1)} ms${p.dns.latencyMs > 200 ? " — slow" : ""}.`);
    if (p.dns.name.length > 60) warnings.push("Very long domain name — can indicate DNS tunneling or tracking.");
  } else if (p.tls) {
    if (p.tls.type === "ClientHello") summary = `Secure connection starting to ${p.tls.sni ?? who(p.dst)} (TLS handshake). Contents will be encrypted.`;
    else if (p.tls.type === "Application Data") summary = `Encrypted data between ${who(p.src)} and ${who(p.dst)} — the contents cannot be read, only size and timing.`;
    else summary = `TLS ${p.tls.type} — part of setting up an encrypted connection.`;
    if (p.tls.version) points.push(`TLS version: ${p.tls.version}.`);
    if (p.tls.cipher) points.push(`Cipher chosen: ${p.tls.cipher}.`);
    if (p.tls.ciphers) points.push(`Client offered ${p.tls.ciphers.length} cipher suites.`);
    if (p.tls.version && /1\.0|1\.1|SSL/.test(p.tls.version)) warnings.push("Outdated TLS version — weak encryption.");
  } else if (p.http) {
    summary = p.http.method
      ? `Unencrypted web request: ${p.http.method} ${p.url ?? `${p.http.host ?? ""}${p.http.path ?? ""}`}.`
      : `Web server replied with status ${p.http.status}${p.http.contentType ? ` (${p.http.contentType})` : ""}.`;
    if (p.http.ua) points.push(`Browser/app identifies as: ${p.http.ua}.`);
    warnings.push("Plain HTTP — anyone on this network can read this page and any form data.");
  } else if (p.proto === "ARP") {
    summary = `ARP: a device is asking "who has this IP?" on the local Wi-Fi — normal network housekeeping.`;
  } else if (p.proto === "ICMP") {
    summary = `ICMP (ping/diagnostics) between ${who(p.src)} and ${who(p.dst)}.`;
  }

  for (const port of [p.dstPort, p.srcPort]) if (port != null && PORTS[port]) { points.push(`Port ${port} = ${PORTS[port]}.`); break; }
  if (p.tcpFlags) points.push(`TCP flags: ${p.tcpFlags}${p.tcpFlags.includes("SYN") && !p.tcpFlags.includes("ACK") ? " (opening a new connection)" : p.tcpFlags.includes("FIN") ? " (closing)" : p.tcpFlags.includes("RST") ? " (connection refused/reset)" : ""}.`);
  if (p.retrans) warnings.push("Retransmission — this data was sent again, a sign of packet loss or a weak Wi-Fi signal.");
  const dp = p.dstPort ?? -1;
  if (!p.http && PLAINTEXT.has(dp) && dp !== 80) warnings.push(`Port ${dp} is a plaintext protocol — passwords may be visible.`);
  if (dp === 23 || dp === 3389 || dp === 445) warnings.push(`Remote-access/sharing port ${dp} — make sure this is expected.`);
  if (warnings.length === 0) points.push("No security concerns detected in this packet.");
  return { summary, points, warnings };
}
