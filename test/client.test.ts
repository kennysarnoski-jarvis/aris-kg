import { describe, expect, it } from "vitest";

import { ArisClient, ArisError } from "../src/client.js";

function fakeFetch(respond: (url: URL, init: RequestInit) => Response) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push({ url, init: init ?? {} });
    return respond(url, init ?? {});
  }) as typeof fetch;
  return { fetchImpl, calls };
}

describe("ArisClient", () => {
  it("searches with the key as a Bearer and keeps descriptions whole up to 1,500 characters", async () => {
    const { fetchImpl, calls } = fakeFetch(() =>
      Response.json({
        query: "CVE-2024-3094",
        results: [{ label: "cve-2024-3094", category: "cve", score: 0.98765, description: "x".repeat(1600) }],
      }),
    );
    const client = new ArisClient({ apiKey: " LOCAL-abc ", fetch: fetchImpl });
    const found = await client.search("cve", "CVE-2024-3094", 5);
    expect(calls[0]!.url.href).toBe("https://youraris.com/api/local/search/cve?query=CVE-2024-3094&limit=5");
    expect((calls[0]!.init.headers as Record<string, string>).Authorization).toBe("Bearer LOCAL-abc");
    expect(found.results[0]).toEqual({
      label: "cve-2024-3094",
      category: "cve",
      score: 0.988,
      description: `${"x".repeat(1500)}…`,
    });
  });

  it("checks dependencies in batches of 500 and maps the structured fields", async () => {
    const { fetchImpl, calls } = fakeFetch((_url, init) => {
      const { packages } = JSON.parse(String(init.body)) as { packages: { name: string; version: string }[] };
      return Response.json({
        results: packages.map((p) =>
          p.name === "express"
            ? {
                name: "express",
                version: "4.16.2",
                ecosystem: "npm",
                cves: [
                  {
                    id: "CVE-2024-29041",
                    severity: "MEDIUM",
                    summary: "Open   redirect.",
                    cvss_score: 6.1,
                    affected_versions: ["<4.19.2"],
                    fixed_in: ["4.19.2"],
                    exploit_available: true,
                  },
                ],
                name_similar: [],
              }
            : { name: p.name, version: p.version, cves: [] },
        ),
        billed_cents: packages.length,
      });
    });
    const client = new ArisClient({ apiKey: "LOCAL-abc", fetch: fetchImpl, baseUrl: "https://aris.test/" });
    const deps = [{ name: "express", version: "4.16.2", ecosystem: "npm" as const }];
    for (let i = 0; i < 501; i++) deps.push({ name: `pkg-${i}`, version: "1.0.0", ecosystem: "npm" });
    const report = await client.checkDependencies(deps);

    expect(calls.map((c) => c.url.href)).toEqual([
      "https://aris.test/api/local/quarry/cve_batch",
      "https://aris.test/api/local/quarry/cve_batch",
    ]);
    expect(report.costCents).toBe(502);
    expect(report.packages).toHaveLength(502);
    expect(report.packages[0]!.vulnerabilities[0]).toEqual({
      id: "CVE-2024-29041",
      severity: "MEDIUM",
      cvssScore: 6.1,
      affectedVersions: ["<4.19.2"],
      fixedIn: ["4.19.2"],
      exploitedInTheWild: true,
      fixCommitUrl: null,
      summary: "Open redirect.",
    });
  });

  it("turns refusals into readable errors", async () => {
    const statusOf = (status: number, body: unknown) =>
      new ArisClient({ apiKey: "LOCAL-abc", fetch: fakeFetch(() => Response.json(body, { status })).fetchImpl });
    await expect(statusOf(402, { detail: "A CVE search costs 1¢ and your balance is too low." }).search("cve", "x")).rejects.toThrow(
      "your balance is too low",
    );
    await expect(statusOf(401, {}).search("cve", "x")).rejects.toThrow("youraris.com/account");
    await expect(statusOf(429, {}).webSearch("x")).rejects.toMatchObject({ status: 429 });
    expect(() => new ArisClient({ apiKey: " " })).toThrow(ArisError);
  });
});
