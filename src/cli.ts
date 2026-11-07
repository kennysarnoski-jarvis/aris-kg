import { resolve } from "node:path";

import { ArisClient, ArisError, type PackageReport, type SearchKind } from "./client.js";
import { readLockfiles } from "./lockfiles.js";
import { VERSION } from "./version.js";

const HELP = `aris-kg ${VERSION} — the Aris knowledge graph for your tools and agents

Usage:
  aris-kg mcp                         Run the MCP server (stdio) for Claude Code, Cursor, Codex…
  aris-kg audit [dir] [options]       Check the lockfiles in dir (default .) for known CVEs
      --fail-on <level>               critical | high | medium | low | none  (default: high)
      --json                          Print the full report as JSON
  aris-kg search <cve|knowledge|code> <query…>

Environment:
  ARIS_API_KEY    Your key from youraris.com/account (required)
  ARIS_BASE_URL   Defaults to https://youraris.com

Calls are billed to your Aris credits: 1¢ per search, 1¢ per package checked, 2¢ per web search.
Exploited-in-the-wild vulnerabilities fail an audit at any level except none.`;

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, moderate: 2, low: 1 };

export function severityRank(severity: string | null): number {
  return SEVERITY_RANK[(severity ?? "").toLowerCase()] ?? 0;
}

function client(): ArisClient {
  return new ArisClient({ apiKey: process.env.ARIS_API_KEY ?? "", baseUrl: process.env.ARIS_BASE_URL });
}

/** Whether a report should fail a build at this threshold. */
export function shouldFail(packages: PackageReport[], failOn: string): boolean {
  if (failOn === "none") return false;
  const threshold = SEVERITY_RANK[failOn] ?? SEVERITY_RANK.high!;
  return packages.some((pkg) =>
    pkg.vulnerabilities.some((v) => v.exploitedInTheWild || severityRank(v.severity) >= threshold),
  );
}

async function audit(args: string[]): Promise<number> {
  let directory = ".";
  let failOn = "high";
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === "--json") json = true;
    else if (arg === "--fail-on") failOn = (args[++i] ?? "").toLowerCase();
    else if (arg.startsWith("--fail-on=")) failOn = arg.slice("--fail-on=".length).toLowerCase();
    else directory = arg;
  }
  if (!(failOn in SEVERITY_RANK) && failOn !== "none") {
    console.error(`Unknown --fail-on level "${failOn}". Use critical, high, medium, low or none.`);
    return 2;
  }

  const lockfiles = readLockfiles(resolve(directory));
  if (lockfiles.length === 0) {
    console.error(
      `No lockfile found in ${resolve(directory)} (package-lock.json, pnpm-lock.yaml, yarn.lock, poetry.lock, requirements.txt, Cargo.lock, go.mod).`,
    );
    return 2;
  }
  const dependencies = lockfiles.flatMap((lock) => lock.dependencies);
  if (dependencies.length === 0) {
    console.error("The lockfiles have no pinned versions to check.");
    return 2;
  }

  const report = await client().checkDependencies(dependencies);
  const vulnerable = report.packages.filter((pkg) => pkg.vulnerabilities.length > 0);
  const failed = shouldFail(report.packages, failOn);

  if (json) {
    console.log(JSON.stringify({ lockfiles: lockfiles.map((l) => l.file), ...report, failed }, null, 2));
    return failed ? 1 : 0;
  }

  for (const lock of lockfiles) console.log(`${lock.file}: ${lock.dependencies.length} pinned packages`);
  console.log("");
  if (vulnerable.length === 0) {
    console.log("No known vulnerabilities.");
  } else {
    const rows = vulnerable
      .flatMap((pkg) => pkg.vulnerabilities.map((v) => ({ pkg, v })))
      .sort(
        (a, b) =>
          Number(b.v.exploitedInTheWild) - Number(a.v.exploitedInTheWild) ||
          severityRank(b.v.severity) - severityRank(a.v.severity) ||
          (b.v.cvssScore ?? 0) - (a.v.cvssScore ?? 0),
      );
    for (const { pkg, v } of rows) {
      const flags = [
        (v.severity ?? "unknown").toUpperCase(),
        v.cvssScore !== null ? `CVSS ${v.cvssScore}` : null,
        v.exploitedInTheWild ? "EXPLOITED IN THE WILD" : null,
      ].filter(Boolean);
      console.log(`${pkg.name}@${pkg.version}  ${v.id ?? "(no id)"}  ${flags.join(" · ")}`);
      if (v.fixedIn.length > 0) console.log(`    fixed in: ${v.fixedIn.join(", ")}`);
      if (v.summary) console.log(`    ${v.summary.slice(0, 200)}`);
    }
  }
  console.log("");
  console.log(
    `${report.packages.length} packages checked, ${vulnerable.length} with known vulnerabilities. Cost: $${(report.costCents / 100).toFixed(2)}.`,
  );
  if (failed) console.log(`Failing: vulnerabilities at or above "${failOn}", or exploited in the wild.`);
  return failed ? 1 : 0;
}

async function search(args: string[]): Promise<number> {
  const kind = args[0] as SearchKind;
  const query = args.slice(1).join(" ").trim();
  if (!["cve", "knowledge", "code"].includes(kind) || !query) {
    console.error("Usage: aris-kg search <cve|knowledge|code> <query…>");
    return 2;
  }
  const found = await client().search(kind, query, 10);
  if (found.results.length === 0) console.log(`Nothing found for "${query}".`);
  for (const result of found.results) {
    console.log(`${result.label}  [${result.category}]`);
    if (result.description) console.log(`    ${result.description.slice(0, 400)}`);
  }
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case "mcp": {
      const { runMcpServer } = await import("./mcp.js");
      await runMcpServer(client());
      return -1; // keep running
    }
    case "audit":
      return audit(rest);
    case "search":
      return search(rest);
    case "--version":
    case "-v":
      console.log(VERSION);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return command === undefined ? 2 : 0;
    default:
      console.error(`Unknown command "${command}".\n\n${HELP}`);
      return 2;
  }
}
