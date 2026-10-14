# Remix of Remix of Remix of Remix of NetScope Insights

Build NetScope: a professional, dark-themed cross-platform network monitoring and packet analysis application inspired by Wireshark, with desktop and mobile support.

Key Requirements:
1. Device Discovery & Isolation:
   - Separate observable network devices into independent cards/rows (IP address, MAC, hostname/vendor, traffic volume, active protocols, and status).
   - Clicking any device isolates the dashboard to inspect all inbound/outbound packets, sessions, and flows for that specific IP.

2. Decoded Traffic & Protocol Inspection:
   - Instead of displaying raw unintelligible binary/encrypted gibberish, decode protocol layers into structured, human-readable insights:
     - DNS queries, response records, query types, latency
     - TLS / HTTPS handshake details, Server Name Indication (SNI), cipher suites, certificate info
     - HTTP/1.1 and HTTP/2 endpoints, methods, status codes, content-types
     - TCP/UDP streams, ports, flags, retransmissions, packet size breakdowns
   - Protocol tree view and raw hex/ASCII viewer for deep-dive packet inspection.

3. Capture & Ingestion:
   - PCAP / PCAPNG file uploader and client-side parser to ingest and analyze real capture files.
   - Built-in live telemetry simulator and WebSocket ingestion endpoint for real-time streaming.
   - Interface selector, start/pause/stop capture controls, filter bar (IP, port, protocol, time).

4. Desktop & Mobile Packaging:
   - Responsive layout designed for desktop workflows and mobile screens.
   - Installable PWA configuration (manifest, service worker, icons) for one-click installation on Windows and Android.
   - Electron configuration (main process file, preload script, package.json scripts) ready for packaging into a Windows .exe installer.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/7d65f993-09cc-454d-b5da-037e450256ed).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
