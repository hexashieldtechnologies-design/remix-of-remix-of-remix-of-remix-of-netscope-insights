#!/usr/bin/env python3
"""
NetScope Capture Agent — streams this machine's live network traffic to the NetScope web app.

Run it, then in NetScope pick "ws0 — Live capture (agent)" and press Start.
The app connects to ws://<this-machine>:9000 (any path) and receives raw
Ethernet frames as binary WebSocket messages, which it decodes live.

No pip installs needed on Linux: capture uses the kernel's AF_PACKET socket.
On macOS / Windows the script falls back to Scapy if it is installed
(Windows additionally needs Npcap: https://npcap.com).

Usage:
  sudo python3 capture_agent.py                 # auto-detect interface, port 9000
  sudo python3 capture_agent.py --iface eth0
  python3 capture_agent.py --port 9443
  python3 capture_agent.py --test               # send demo frames (no root needed)
"""
import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------- WebSocket hub
def ws_frame(payload: bytes, op: int = 0x82) -> bytes:
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", op, n)            # FIN + opcode (0x82 binary, 0x81 text)
    elif n < 65536:
        head = struct.pack("!BBH", op, 126, n)
    else:
        head = struct.pack("!BBQ", op, 127, n)
    return head + payload


class Hub:
    def __init__(self):
        self.clients = set()
        self.lock = threading.Lock()
        self.sent = 0
        self.bytes = 0

    def add(self, conn):
        with self.lock:
            self.clients.add(conn)

    def remove(self, conn):
        with self.lock:
            self.clients.discard(conn)

    def count(self):
        with self.lock:
            return len(self.clients)

    def broadcast(self, data: bytes, op: int = 0x82):
        frame = ws_frame(data, op)
        dead = []
        with self.lock:
            for c in self.clients:
                try:
                    c.sendall(frame)
                    if op == 0x82:
                        self.sent += 1
                        self.bytes += len(data)
                except OSError:
                    dead.append(c)
            for c in dead:
                self.clients.discard(c)

    def send_text(self, text: str):
        self.broadcast(text.encode(), 0x81)


def handle_client(conn, addr, hub):
    print(f"[+] NetScope connected: {addr[0]}:{addr[1]}")
    try:
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = conn.recv(4096)
            if not chunk:
                return
            req += chunk
        key = ""
        for line in req.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode()
        if not key:
            return
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )
        hub.add(conn)
        # Keep reading (and ignore) client frames so closes are detected promptly.
        while True:
            if not conn.recv(4096):
                break
    except OSError:
        pass
    finally:
        hub.remove(conn)
        conn.close()
        print(f"[-] NetScope disconnected: {addr[0]}:{addr[1]}")


def ws_server(port, hub):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"[*] WebSocket server listening on ws://0.0.0.0:{port} (all interfaces)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, hub), daemon=True).start()


# ---------------------------------------------------------------- capture
def auto_iface():
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route") as f:
                for line in f.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
                        return parts[0]
        except OSError:
            pass
        try:
            with open("/proc/net/dev") as f:
                for line in f.read().splitlines()[2:]:
                    name = line.split(":")[0].strip()
                    if name not in ("lo",):
                        return name
        except OSError:
            pass
    return None


def stats_loop(hub):
    last = (0, 0)
    while True:
        time.sleep(5)
        cur = (hub.sent, hub.bytes)
        if cur != last:
            print(f"[*] {hub.sent} frames, {hub.bytes/1024:.0f} KB sent, {hub.count()} client(s)")
            last = cur


def capture_afpacket(hub, iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((iface, 0))
    print(f"[*] AF_PACKET capture on '{iface}'")
    while True:
        data = s.recv(65535)
        if data:
            hub.broadcast(data)


def capture_scapy(hub, iface):
    from scapy.all import sniff  # noqa
    print(f"[*] Scapy capture on '{iface or 'default'}'")
    sniff(prn=lambda p: hub.broadcast(bytes(p)), iface=iface, store=False)


def demo_frames(n=100000):
    """Synthetic Ethernet/IP/UDP/DNS query frames for --test (no root needed)."""
    out = []
    for i in range(n):
        q = struct.pack("!HHHHHH", i & 0xFFFF, 0x0100, 1, 0, 0, 0) + b"\x0dnetscope-test\x03com\x00" + b"\x00\x01\x00\x01"
        udp = struct.pack("!HHHH", 50000 + (i % 1000), 53, 8 + len(q), 0) + q
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i, 0x4000, 64, 17, 0,
                         socket.inet_aton("192.168.1.14"), socket.inet_aton("8.8.8.8"))
        eth = b"\x01\x02\x03\x04\x05\x06" + b"\xaa\xbb\xcc\xdd\xee\x0f" + b"\x08\x00"
        out.append(eth + ip + udp)
    return out


def main():
    ap = argparse.ArgumentParser(description="NetScope live capture agent")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--iface", default=None, help="interface to capture on (default: auto-detect)")
    ap.add_argument("--scapy", action="store_true", help="force the Scapy capture backend")
    ap.add_argument("--test", action="store_true", help="send demo frames instead of capturing")
    args = ap.parse_args()

    hub = Hub()
    threading.Thread(target=ws_server, args=(args.port, hub), daemon=True).start()
    threading.Thread(target=stats_loop, args=(hub,), daemon=True).start()

    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
        lan = next((ip for ip in ips if not ip.startswith("127.")), "127.0.0.1")
    except OSError:
        lan = "127.0.0.1"

    print("=" * 64)
    print("  NetScope Capture Agent")
    print(f"  URL for this PC:        ws://localhost:{args.port}")
    print(f"  URL for phones on LAN:  ws://{lan}:{args.port}")
    print("  In NetScope: pick 'ws0 — Live capture (agent)' -> Start")
    print("=" * 64)

    if args.test:
        print("[*] TEST mode: streaming demo frames at ~25 fps")
        frames = demo_frames(25)
        while True:
            for f in frames:
                hub.broadcast(f)
                time.sleep(0.04)
    else:
        iface = args.iface or auto_iface()
        if sys.platform.startswith("linux") and not args.scapy:
            try:
                capture_afpacket(hub, iface or "eth0")
            except PermissionError:
                print("[!] Permission denied: re-run with sudo")
                sys.exit(1)
        else:
            try:
                capture_scapy(hub, iface)
            except ImportError:
                print("[!] Scapy not installed. Run:  pip install scapy")
                print("    (Windows also needs Npcap: https://npcap.com)")
                sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Bye")
