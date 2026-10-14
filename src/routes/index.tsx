import { createFileRoute } from "@tanstack/react-router";
import { NetScope } from "@/components/netscope/NetScope";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NetScope — Network Monitoring & Packet Analysis" },
      { name: "description", content: "Discover devices, decode DNS, TLS and HTTP traffic, and inspect packets from live streams or PCAP files." },
      { property: "og:title", content: "NetScope — Network Monitoring & Packet Analysis" },
      { property: "og:description", content: "Decode DNS, TLS, HTTP and TCP/UDP traffic per device, with protocol tree and hex views." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: NetScope,
});
