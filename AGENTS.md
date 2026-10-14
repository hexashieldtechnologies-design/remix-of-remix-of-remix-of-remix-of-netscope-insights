<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

# NetScope — project notes

## Architecture decisions
- All packet parsing/decoding runs client-side (browser); no server-side capture. Live data enters via WebSocket only — the app connects OUT to a user-provided URL. Message format: raw binary frame, or JSON `{hex|base64, ts?, linktype?}` (single object or array).
- The live simulator builds real wire-format Ethernet frames (`src/lib/netscope/simulator.ts`) so it exercises the same decoder as PCAP imports — never special-case simulator data.
- New protocol decode logic belongs in `src/lib/netscope/decode.ts`; layers carry byte ranges `[start, end]` so the protocol tree can highlight the hex viewer.
- The four core byte-parsing files (`src/lib/netscope/*`, `NetScope.tsx`) use `// @ts-nocheck`: per-byte index access fights the strict noUncheckedIndexedAccess config. Revisit if the config loosens; do not add more ts-nocheck files.
- PWA: manifest + icons exist; there is intentionally NO service worker yet (added later — see roadmap).
- Electron (`electron/main.cjs`) loads a URL from `NETSCOPE_URL` (default http://localhost:8080) rather than bundling the app; packaging scripts are in package.json.
