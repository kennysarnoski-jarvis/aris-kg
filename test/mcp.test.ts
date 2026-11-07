import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";

import { ArisClient } from "../src/client.js";
import { createServer } from "../src/mcp.js";

describe("MCP server", () => {
  it("lists the five tools with guidance, and answers a CVE search", async () => {
    const fetchImpl = (async () =>
      Response.json({ query: "CVE-2024-3094", results: [{ label: "cve-2024-3094", category: "cve", score: 1, description: "xz backdoor" }] })) as typeof fetch;
    const server = createServer(new ArisClient({ apiKey: "LOCAL-abc", fetch: fetchImpl }));
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: "test", version: "1.0.0" });
    await client.connect(clientSide);

    expect(client.getInstructions()).toContain("Use them without being asked");
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      "aris_check_dependencies",
      "aris_search_code",
      "aris_search_cve",
      "aris_search_knowledge",
      "aris_web_search",
    ]);
    const result = await client.callTool({ name: "aris_search_cve", arguments: { query: "CVE-2024-3094" } });
    expect(result.isError).toBeFalsy();
    expect(JSON.stringify(result.content)).toContain("xz backdoor");
    await client.close();
  });

  it("reports an API refusal as a tool error, not a crash", async () => {
    const fetchImpl = (async () => Response.json({ detail: "Rate limit: 120 calls a minute." }, { status: 429 })) as typeof fetch;
    const server = createServer(new ArisClient({ apiKey: "LOCAL-abc", fetch: fetchImpl }));
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: "test", version: "1.0.0" });
    await client.connect(clientSide);
    const result = await client.callTool({ name: "aris_web_search", arguments: { query: "x" } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain("Rate limit");
    await client.close();
  });
});
