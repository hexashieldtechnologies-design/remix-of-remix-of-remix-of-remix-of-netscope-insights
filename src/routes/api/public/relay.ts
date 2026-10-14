import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

// Remote capture relay: the agent (anywhere in the world) POSTs frames for a room code,
// the NetScope browser polls GET with the same code. The room code is the shared secret.
const ROOM = z.string().regex(/^[A-Z0-9-]{8,40}$/);
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const PushBody = z.object({
  room: ROOM,
  items: z
    .array(z.object({ kind: z.enum(["frame", "devices"]), payload: z.string().min(1).max(200000), ts: z.number().optional() }))
    .min(1)
    .max(500),
});

const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { ...CORS, "Cache-Control": "no-store" } });

export const Route = createFileRoute("/api/public/relay")({
  server: {
    handlers: {
      OPTIONS: async () => new Response(null, { status: 204, headers: CORS }),
      POST: async ({ request }) => {
        let parsed;
        try { parsed = PushBody.safeParse(await request.json()); } catch { return json({ error: "bad json" }, 400); }
        if (!parsed.success) return json({ error: "invalid body" }, 400);
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const rows = parsed.data.items.map((i) => ({ room: parsed.data.room, kind: i.kind, payload: i.payload, ts: i.ts ?? Date.now() }));
        const { error } = await supabaseAdmin.from("relay_frames").insert(rows);
        if (error) { console.error("relay insert", error); return json({ error: "store failed" }, 500); }
        if (Math.random() < 0.05) {
          await supabaseAdmin.from("relay_frames").delete().lt("created_at", new Date(Date.now() - 15 * 60000).toISOString());
        }
        return json({ ok: true, stored: rows.length });
      },
      GET: async ({ request }) => {
        const url = new URL(request.url);
        const room = ROOM.safeParse(url.searchParams.get("room"));
        if (!room.success) return json({ error: "invalid room" }, 400);
        const after = Math.max(0, Number(url.searchParams.get("after")) || 0);
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { data, error } = await supabaseAdmin
          .from("relay_frames")
          .select("id, kind, payload, ts")
          .eq("room", room.data)
          .gt("id", after)
          .order("id", { ascending: true })
          .limit(1000);
        if (error) { console.error("relay read", error); return json({ error: "read failed" }, 500); }
        return json({ items: data ?? [] });
      },
    },
  },
});
