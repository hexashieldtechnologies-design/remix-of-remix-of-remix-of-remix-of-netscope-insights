import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, FileUp, Pause, Play, Plug, Radio, Square, Trash2, X, Search, Smartphone, Laptop, Router, Cpu, Tv, Server } from "lucide-react";
import { Analyzer, decodeFrame, type Packet, type Proto, type Field } from "@/lib/netscope/decode";
import { parseCapture } from "@/lib/netscope/pcap";
import { scenario, SIM_DEVICES } from "@/lib/netscope/simulator";

const MAX = 20000;
const PROTO_CLS: Record<Proto, string> = {
  DNS: "text-p-dns", TLS: "text-p-tls", HTTP: "text-p-http", TCP: "text-p-tcp", UDP: "text-p-udp",
  ICMP: "text-p-icmp", ARP: "text-p-arp", IPv6: "text-muted-foreground", OTHER: "text-muted-foreground",
};
const OUI: Record<string, string> = { "3c:22:fb": "Apple", "a4:83:e7": "Apple", "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "00:1a:11": "Google", "f4:f2:6d": "TP-Link", "50:02:91": "Espressif", "24:0a:c4": "Espressif", "d8:bb:c1": "Micro-Star", "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:0c:29": "VMware" };
const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fd)/.test(ip);
const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const IFACES = ["sim0 — Live simulator", "ws0 — WebSocket stream", "file — PCAP import"];

interface Device { ip: string; mac?: string; host?: string; vendor?: string; pkts: number; bytesIn: number; bytesOut: number; protos: Set<Proto>; last: number; peers: Set<string> }

function deviceIcon(d: Device) {
  const v = `${d.vendor} ${d.host}`.toLowerCase();
  if (v.includes("gateway") || v.includes("tp-link")) return Router;
  if (v.includes("iphone") || v.includes("android")) return Smartphone;
  if (v.includes("cast") || v.includes("tv")) return Tv;
  if (v.includes("esp") || v.includes("pi")) return Cpu;
  if (v.includes("mac") || v.includes("desktop") || v.includes("win")) return Laptop;
  return Server;
}

function matches(p: Packet, q: string, latest: number) {
  for (const tok of q.trim().toLowerCase().split(/\s+/).filter(Boolean)) {
    const [k, v] = tok.includes(":") && !/^[\da-f:]+$/.test(tok) ? [tok.slice(0, tok.indexOf(":")), tok.slice(tok.indexOf(":") + 1)] : ["", tok];
    if (k === "ip") { if (p.src !== v && p.dst !== v) return false; }
    else if (k === "port") { if (String(p.srcPort) !== v && String(p.dstPort) !== v) return false; }
    else if (k === "proto") { if (p.proto.toLowerCase() !== v && !(v === "tcp" && p.tcpFlags !== undefined) && !(v === "udp" && p.proto === "DNS")) return false; }
    else if (k === "last") { const s = parseFloat(v) * (v.endsWith("m") ? 60 : 1); if (latest - p.ts > s * 1000) return false; }
    else if (k === "retrans") { if (!p.retrans) return false; }
    else if (!`${p.src} ${p.dst} ${p.info} ${p.proto} ${p.srcPort} ${p.dstPort}`.toLowerCase().includes(v)) return false;
  }
  return true;
}

export function NetScope() {
  const pkts = useRef<Packet[]>([]);
  const analyzer = useRef(new Analyzer());
  const nextId = useRef(1);
  const hosts = useRef(new Map<string, string>());
  const [ver, setVer] = useState(0);
  const [state, setState] = useState<"stopped" | "running" | "paused">("stopped");
  const [iface, setIface] = useState(IFACES[0]);
  const [filter, setFilter] = useState("");
  const [device, setDevice] = useState<string | null>(null);
  const [selId, setSelId] = useState<number | null>(null);
  const [hl, setHl] = useState<[number, number] | null>(null);
  const [tab, setTab] = useState<"packets" | "flows" | "dns" | "tls" | "http">("packets");
  const [wsUrl, setWsUrl] = useState("ws://localhost:9000/capture");
  const [wsStatus, setWsStatus] = useState("disconnected");
  const [msg, setMsg] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const ingest = useCallback((frames: { data: Uint8Array; ts: number; linktype?: number }[]) => {
    for (const f of frames) {
      const p = analyzer.current.apply(decodeFrame(f.data, f.ts, nextId.current++, f.linktype ?? 1));
      if (p.dns?.response) p.dns.answers.forEach((a) => { const ip = a.split(" ")[1]; if (ip) hosts.current.set(ip, p.dns!.name); });
      if (p.tls?.sni) hosts.current.set(p.dst, p.tls.sni);
      pkts.current.push(p);
    }
    if (pkts.current.length > MAX) pkts.current.splice(0, pkts.current.length - MAX);
    setVer((v) => v + 1);
  }, []);

  // Simulator
  useEffect(() => {
    if (state !== "running" || !iface.startsWith("sim")) return;
    const gen = scenario();
    SIM_DEVICES.forEach((d) => hosts.current.set(d.ip, d.host));
    let t = 0;
    const iv = setInterval(() => {
      const batch: { data: Uint8Array; ts: number }[] = [];
      for (let i = 0; i < 1 + Math.floor(Math.random() * 3); i++)
        for (const fr of gen.next().value!) batch.push({ data: fr, ts: Date.now() + (t += 0.2) % 1 });
      ingest(batch);
    }, 250);
    return () => clearInterval(iv);
  }, [state, iface, ingest]);

  // WebSocket ingestion: messages are JSON {hex|base64, ts?, linktype?} or an array of them
  useEffect(() => {
    if (state !== "running" || !iface.startsWith("ws")) return;
    let ws: WebSocket;
    try { ws = new WebSocket(wsUrl); } catch { setWsStatus("invalid URL"); return; }
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;
    setWsStatus("connecting…");
    ws.onopen = () => setWsStatus("connected");
    ws.onerror = () => setWsStatus("error");
    ws.onclose = () => setWsStatus("disconnected");
    ws.onmessage = (e) => {
      if (e.data instanceof ArrayBuffer) return ingest([{ data: new Uint8Array(e.data), ts: Date.now() }]);
      try {
        const j = JSON.parse(e.data);
        const arr = Array.isArray(j) ? j : [j];
        ingest(arr.map((m: { hex?: string; base64?: string; ts?: number; linktype?: number }) => ({
          data: m.hex ? new Uint8Array(m.hex.match(/../g)!.map((h) => parseInt(h, 16))) : Uint8Array.from(atob(m.base64 ?? ""), (c) => c.charCodeAt(0)),
          ts: m.ts ?? Date.now(), linktype: m.linktype,
        })));
      } catch { /* ignore malformed */ }
    };
    return () => ws.close();
  }, [state, iface, wsUrl, ingest]);

  const clear = () => { pkts.current = []; analyzer.current = new Analyzer(); nextId.current = 1; setSelId(null); setDevice(null); setVer((v) => v + 1); };

  const onFile = async (f: File) => {
    try {
      const frames = parseCapture(await f.arrayBuffer());
      setState("stopped");
      setIface(IFACES[2]);
      clear();
      ingest(frames.map((fr) => ({ ...fr, data: fr.data.slice() })));
      setMsg(`Imported ${frames.length.toLocaleString()} packets from ${f.name}`);
    } catch (e) { setMsg((e as Error).message); }
  };

  const all = pkts.current;
  const latest = all.length ? all[all.length - 1].ts : Date.now();

  const devices = useMemo(() => {
    const m = new Map<string, Device>();
    const get = (ip: string) => { let d = m.get(ip); if (!d) m.set(ip, (d = { ip, pkts: 0, bytesIn: 0, bytesOut: 0, protos: new Set(), last: 0, peers: new Set() })); return d; };
    for (const p of all) {
      if (p.src === "?") continue;
      for (const [ip, out] of [[p.src, true], [p.dst, false]] as const) {
        if (!isPrivate(ip) || ip.endsWith(".255")) continue;
        const d = get(ip);
        d.pkts++;
        if (out) { d.bytesOut += p.length; d.mac ??= p.srcMac; } else { d.bytesIn += p.length; if (p.proto !== "ARP") d.mac ??= p.dstMac; }
        d.protos.add(p.proto);
        d.last = Math.max(d.last, p.ts);
        d.peers.add(out ? p.dst : p.src);
      }
    }
    for (const d of m.values()) {
      d.host = hosts.current.get(d.ip);
      d.vendor = d.mac ? OUI[d.mac.slice(0, 8)] ?? "Unknown vendor" : undefined;
    }
    return [...m.values()].sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ver]);

  const view = useMemo(() => all.filter((p) => (!device || p.src === device || p.dst === device) && matches(p, filter, latest)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [ver, device, filter]);

  const sel = useMemo(() => all.find((p) => p.id === selId) ?? null, [selId, ver, all]);
  const dev = devices.find((d) => d.ip === device);

  const stats = useMemo(() => {
    const by: Partial<Record<Proto, number>> = {};
    let bytes = 0, retrans = 0;
    view.forEach((p) => { by[p.proto] = (by[p.proto] ?? 0) + 1; bytes += p.length; if (p.retrans) retrans++; });
    return { by, bytes, retrans };
  }, [view]);

  return (
    <div className="flex h-dvh flex-col bg-background text-foreground">
      {/* Toolbar */}
      <header className="flex flex-wrap items-center gap-2 border-b border-border bg-sidebar px-3 py-2">
        <div className="mr-2 flex items-center gap-2">
          <img src="/icon-192.png" alt="" width={28} height={28} className="rounded" />
          <span className="font-semibold tracking-tight">NetScope</span>
        </div>
        <select value={iface} onChange={(e) => { setState("stopped"); setIface(e.target.value); }} className="h-8 rounded border border-input bg-background px-2 font-mono text-xs" aria-label="Interface">
          {IFACES.map((i) => <option key={i}>{i}</option>)}
        </select>
        <div className="flex items-center gap-1">
          <ToolBtn label={state === "running" ? "Pause" : "Start"} onClick={() => setState(state === "running" ? "paused" : "running")} disabled={iface.startsWith("file")} primary>
            {state === "running" ? <Pause className="size-4" /> : <Play className="size-4" />}
          </ToolBtn>
          <ToolBtn label="Stop" onClick={() => setState("stopped")} disabled={state === "stopped"}><Square className="size-4" /></ToolBtn>
          <ToolBtn label="Clear" onClick={clear}><Trash2 className="size-4" /></ToolBtn>
          <ToolBtn label="Open PCAP" onClick={() => fileRef.current?.click()}><FileUp className="size-4" /></ToolBtn>
          <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
        </div>
        {iface.startsWith("ws") && (
          <div className="flex items-center gap-1">
            <Plug className="size-4 text-muted-foreground" />
            <input value={wsUrl} onChange={(e) => setWsUrl(e.target.value)} className="h-8 w-56 rounded border border-input bg-background px-2 font-mono text-xs" aria-label="WebSocket URL" />
            <span className="font-mono text-xs text-muted-foreground">{wsStatus}</span>
          </div>
        )}
        <div className="ml-auto flex items-center gap-2 font-mono text-xs">
          <span className={`inline-flex items-center gap-1 rounded px-2 py-1 ${state === "running" ? "bg-accent text-primary" : "bg-muted text-muted-foreground"}`}>
            <Radio className={`size-3 ${state === "running" ? "animate-pulse" : ""}`} /> {state.toUpperCase()}
          </span>
          <span className="text-muted-foreground">{all.length.toLocaleString()} pkts</span>
        </div>
      </header>

      {/* Filter */}
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5">
        <Search className="size-4 text-muted-foreground" />
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter: ip:192.168.1.14  port:443  proto:dns  last:30s  retrans:  or free text…" className="h-8 flex-1 rounded border border-input bg-background px-2 font-mono text-xs outline-none focus:border-ring" />
        {filter && <button onClick={() => setFilter("")} aria-label="Clear filter"><X className="size-4 text-muted-foreground" /></button>}
      </div>
      {msg && <div className="flex items-center justify-between bg-accent px-3 py-1 text-xs">{msg}<button onClick={() => setMsg(null)} aria-label="Dismiss"><X className="size-3" /></button></div>}

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        {/* Devices */}
        <aside className="shrink-0 border-b border-border bg-sidebar lg:w-72 lg:border-b-0 lg:border-r">
          <div className="flex items-center justify-between px-3 py-2 text-xs uppercase tracking-wider text-muted-foreground">
            <span>Devices ({devices.length})</span>
            {device && <button className="normal-case text-primary" onClick={() => setDevice(null)}>Show all</button>}
          </div>
          <div className="flex gap-2 overflow-x-auto px-2 pb-2 lg:max-h-[calc(100dvh-140px)] lg:flex-col lg:overflow-y-auto lg:overflow-x-hidden">
            {devices.length === 0 && <p className="px-2 py-4 text-sm text-muted-foreground">Press Start to run the live simulator, or open a PCAP file.</p>}
            {devices.map((d) => {
              const Icon = deviceIcon(d);
              const active = latest - d.last < 10000;
              return (
                <button key={d.ip} onClick={() => setDevice(device === d.ip ? null : d.ip)}
                  className={`w-60 shrink-0 rounded-md border p-2.5 text-left transition-colors lg:w-full ${device === d.ip ? "border-primary bg-accent" : "border-border bg-card hover:border-ring/50"}`}>
                  <div className="flex items-center gap-2">
                    <Icon className="size-4 text-primary" />
                    <span className="truncate text-sm font-medium">{d.host ?? d.ip}</span>
                    <span className={`ml-auto size-2 rounded-full ${active ? "bg-primary" : "bg-muted-foreground/40"}`} title={active ? "Active" : "Idle"} />
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{d.ip}{d.mac && ` · ${d.mac}`}</div>
                  <div className="text-[11px] text-muted-foreground">{d.vendor}</div>
                  <div className="mt-1.5 flex items-center justify-between font-mono text-[11px]">
                    <span>↑{fmtBytes(d.bytesOut)} ↓{fmtBytes(d.bytesIn)}</span>
                    <span className="text-muted-foreground">{d.pkts} pkts</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {[...d.protos].map((p) => <span key={p} className={`rounded bg-muted px-1 font-mono text-[10px] ${PROTO_CLS[p]}`}>{p}</span>)}
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        {/* Main */}
        <main className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-3 py-2 text-xs">
            {dev ? <span className="font-medium text-primary">Isolated: {dev.host ?? dev.ip} · {dev.peers.size} peers</span> : <span className="text-muted-foreground">All traffic</span>}
            <span className="font-mono">{view.length.toLocaleString()} pkts · {fmtBytes(stats.bytes)}</span>
            {(Object.keys(stats.by) as Proto[]).map((p) => <span key={p} className={`font-mono ${PROTO_CLS[p]}`}>{p} {stats.by[p]}</span>)}
            {stats.retrans > 0 && <span className="font-mono text-warning">retrans {stats.retrans}</span>}
          </div>
          <nav className="flex gap-1 overflow-x-auto border-b border-border px-2">
            {(["packets", "flows", "dns", "tls", "http"] as const).map((t) => (
              <button key={t} onClick={() => setTab(t)} className={`border-b-2 px-3 py-2 text-xs font-medium uppercase tracking-wide ${tab === t ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}>{t}</button>
            ))}
          </nav>
          <div className="min-h-0 flex-1 overflow-auto">
            {tab === "packets" && <PacketTable rows={view} selId={selId} onSel={(id) => { setSelId(id); setHl(null); }} t0={all[0]?.ts ?? 0} />}
            {tab === "flows" && <Flows rows={view} />}
            {tab === "dns" && <Insight rows={view.filter((p) => p.dns)} cols={["Name", "Type", "Kind", "Answers", "Latency"]} cell={(p) => [p.dns!.name, p.dns!.qtype, p.dns!.response ? "response" : "query", p.dns!.answers.join(", "), p.dns!.latencyMs != null ? `${p.dns!.latencyMs.toFixed(1)} ms` : ""]} onSel={(id) => { setSelId(id); setTab("packets"); }} />}
            {tab === "tls" && <Insight rows={view.filter((p) => p.tls && p.tls.type !== "Application Data")} cols={["Message", "SNI / CN", "Version", "Cipher", "Server"]} cell={(p) => [p.tls!.type, p.tls!.sni ?? p.tls!.cert ?? hosts.current.get(p.src) ?? "", p.tls!.version ?? "", p.tls!.cipher ?? (p.tls!.ciphers ? `${p.tls!.ciphers.length} offered` : ""), p.tls!.type === "ClientHello" ? p.dst : p.src]} onSel={(id) => { setSelId(id); setTab("packets"); }} />}
            {tab === "http" && <Insight rows={view.filter((p) => p.http)} cols={["Method / Status", "Host", "Path", "Content-Type", "Version"]} cell={(p) => [p.http!.method ?? String(p.http!.status ?? ""), p.http!.host ?? p.src, p.http!.path ?? "", p.http!.contentType ?? "", p.http!.version]} onSel={(id) => { setSelId(id); setTab("packets"); }} />}
          </div>
          {sel && tab === "packets" && (
            <div className="grid max-h-[45%] min-h-48 shrink-0 grid-cols-1 border-t border-border md:grid-cols-2">
              <ProtoTree p={sel} onField={(f) => setHl(f.r ?? null)} hl={hl} />
              <HexView bytes={sel.bytes} hl={hl} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function ToolBtn({ children, label, onClick, disabled, primary }: { children: React.ReactNode; label: string; onClick: () => void; disabled?: boolean; primary?: boolean }) {
  return (
    <button title={label} aria-label={label} onClick={onClick} disabled={disabled}
      className={`inline-flex h-8 items-center gap-1 rounded px-2 text-xs disabled:opacity-40 ${primary ? "bg-primary text-primary-foreground hover:bg-primary/90" : "border border-border hover:bg-muted"}`}>
      {children}<span className="hidden sm:inline">{label}</span>
    </button>
  );
}

function PacketTable({ rows, selId, onSel, t0 }: { rows: Packet[]; selId: number | null; onSel: (id: number) => void; t0: number }) {
  const shown = rows.slice(-600);
  const ref = useRef<HTMLDivElement>(null);
  return (
    <div ref={ref}>
      <table className="w-full font-mono text-[11px]">
        <thead className="sticky top-0 bg-card text-left text-muted-foreground">
          <tr>{["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"].map((h) => <th key={h} className="whitespace-nowrap px-2 py-1.5 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody>
          {shown.length === 0 && <tr><td colSpan={7} className="px-3 py-8 text-center text-muted-foreground"><Activity className="mx-auto mb-2 size-5" />No packets match.</td></tr>}
          {shown.map((p) => (
            <tr key={p.id} onClick={() => onSel(p.id)} className={`cursor-pointer border-b border-border/40 ${p.id === selId ? "bg-accent" : p.retrans ? "bg-warning/10" : "hover:bg-muted"}`}>
              <td className="px-2 py-1 text-muted-foreground">{p.id}</td>
              <td className="px-2 py-1 whitespace-nowrap">{((p.ts - t0) / 1000).toFixed(3)}</td>
              <td className="px-2 py-1 whitespace-nowrap">{p.src}{p.srcPort != null && <span className="text-muted-foreground">:{p.srcPort}</span>}</td>
              <td className="px-2 py-1 whitespace-nowrap">{p.dst}{p.dstPort != null && <span className="text-muted-foreground">:{p.dstPort}</span>}</td>
              <td className={`px-2 py-1 font-medium ${PROTO_CLS[p.proto]}`}>{p.proto}</td>
              <td className="px-2 py-1">{p.length}</td>
              <td className={`max-w-[28rem] truncate px-2 py-1 ${p.retrans ? "text-warning" : ""}`}>{p.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 600 && <p className="p-2 text-center text-xs text-muted-foreground">Showing latest 600 of {rows.length.toLocaleString()} — refine the filter to narrow.</p>}
    </div>
  );
}

function Flows({ rows }: { rows: Packet[] }) {
  const flows = useMemo(() => {
    const m = new Map<string, { a: string; b: string; proto: string; pkts: number; bytes: number; first: number; last: number; retrans: number; label?: string }>();
    for (const p of rows) {
      if (p.srcPort == null) continue;
      const x = `${p.src}:${p.srcPort}`, y = `${p.dst}:${p.dstPort}`;
      const [a, b] = x < y ? [x, y] : [y, x];
      const l4 = p.tcpFlags !== undefined ? "TCP" : "UDP";
      const k = `${l4} ${a} ${b}`;
      let f = m.get(k);
      if (!f) m.set(k, (f = { a, b, proto: l4, pkts: 0, bytes: 0, first: p.ts, last: p.ts, retrans: 0 }));
      f.pkts++; f.bytes += p.length; f.last = p.ts; if (p.retrans) f.retrans++;
      f.label ??= p.tls?.sni ?? p.http?.host ?? p.dns?.name;
    }
    return [...m.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 300);
  }, [rows]);
  return (
    <table className="w-full font-mono text-[11px]">
      <thead className="sticky top-0 bg-card text-left text-muted-foreground"><tr>{["Proto", "Endpoint A", "Endpoint B", "App", "Pkts", "Bytes", "Duration", "Retrans"].map((h) => <th key={h} className="px-2 py-1.5 font-medium">{h}</th>)}</tr></thead>
      <tbody>{flows.map((f) => (
        <tr key={`${f.proto}${f.a}${f.b}`} className="border-b border-border/40 hover:bg-muted">
          <td className="px-2 py-1">{f.proto}</td><td className="px-2 py-1">{f.a}</td><td className="px-2 py-1">{f.b}</td>
          <td className="px-2 py-1 text-primary">{f.label ?? ""}</td><td className="px-2 py-1">{f.pkts}</td><td className="px-2 py-1">{fmtBytes(f.bytes)}</td>
          <td className="px-2 py-1">{((f.last - f.first) / 1000).toFixed(2)}s</td><td className={`px-2 py-1 ${f.retrans ? "text-warning" : "text-muted-foreground"}`}>{f.retrans}</td>
        </tr>))}</tbody>
    </table>
  );
}

function Insight({ rows, cols, cell, onSel }: { rows: Packet[]; cols: string[]; cell: (p: Packet) => string[]; onSel: (id: number) => void }) {
  return (
    <table className="w-full font-mono text-[11px]">
      <thead className="sticky top-0 bg-card text-left text-muted-foreground"><tr><th className="px-2 py-1.5 font-medium">No.</th>{cols.map((c) => <th key={c} className="px-2 py-1.5 font-medium">{c}</th>)}</tr></thead>
      <tbody>
        {rows.length === 0 && <tr><td colSpan={cols.length + 1} className="px-3 py-8 text-center text-muted-foreground">Nothing decoded yet.</td></tr>}
        {rows.slice(-400).reverse().map((p) => (
          <tr key={p.id} onClick={() => onSel(p.id)} className="cursor-pointer border-b border-border/40 hover:bg-muted">
            <td className="px-2 py-1 text-muted-foreground">{p.id}</td>
            {cell(p).map((c, i) => <td key={i} className="max-w-[24rem] truncate px-2 py-1">{c}</td>)}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ProtoTree({ p, onField, hl }: { p: Packet; onField: (f: Field) => void; hl: [number, number] | null }) {
  const [closed, setClosed] = useState<Set<number>>(new Set());
  return (
    <div className="overflow-auto border-b border-border p-2 font-mono text-[11px] md:border-b-0 md:border-r">
      {p.layers.map((l, i) => (
        <div key={i} className="mb-1">
          <button onClick={() => { const s = new Set(closed); s.has(i) ? s.delete(i) : s.add(i); setClosed(s); l.r && onField({ k: "", v: "", r: l.r }); }} className="w-full text-left font-semibold text-primary hover:underline">
            {closed.has(i) ? "▸" : "▾"} {l.name}
          </button>
          {!closed.has(i) && l.fields.map((f, j) => (
            <button key={j} onClick={() => onField(f)} className={`block w-full truncate pl-4 text-left hover:bg-muted ${hl && f.r && hl[0] === f.r[0] && hl[1] === f.r[1] ? "bg-accent" : ""}`}>
              <span className="text-muted-foreground">{f.k}:</span> {f.v}
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

function HexView({ bytes, hl }: { bytes: Uint8Array; hl: [number, number] | null }) {
  const lines = [];
  for (let o = 0; o < bytes.length; o += 16) {
    const row = Array.from(bytes.slice(o, o + 16));
    const on = (i: number) => hl && o + i >= hl[0] && o + i < hl[1];
    lines.push(
      <div key={o} className="flex gap-3 whitespace-pre">
        <span className="text-muted-foreground">{o.toString(16).padStart(4, "0")}</span>
        <span>{row.map((b, i) => <span key={i} className={on(i) ? "bg-primary text-primary-foreground" : ""}>{b.toString(16).padStart(2, "0")}{i === 7 ? "  " : " "}</span>)}{"   ".repeat(16 - row.length)}</span>
        <span className="text-muted-foreground">{row.map((b, i) => <span key={i} className={on(i) ? "bg-primary text-primary-foreground" : ""}>{b >= 32 && b < 127 ? String.fromCharCode(b) : "·"}</span>)}</span>
      </div>,
    );
  }
  return <div className="overflow-auto p-2 font-mono text-[11px] leading-5">{lines}</div>;
}
