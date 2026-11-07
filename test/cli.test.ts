import { describe, expect, it } from "vitest";

import { shouldFail } from "../src/cli.js";
import type { PackageReport } from "../src/client.js";

const pkg = (severity: string | null, exploited = false): PackageReport => ({
  name: "x",
  version: "1.0.0",
  ecosystem: "npm",
  possibleMatches: [],
  vulnerabilities: [
    { id: "CVE-1", severity, cvssScore: null, affectedVersions: [], fixedIn: [], exploitedInTheWild: exploited, fixCommitUrl: null, summary: "" },
  ],
});

describe("audit failure rule", () => {
  it("fails at or above the threshold, on anything exploited, and never with none", () => {
    expect(shouldFail([pkg("HIGH")], "high")).toBe(true);
    expect(shouldFail([pkg("MEDIUM")], "high")).toBe(false);
    expect(shouldFail([pkg("moderate")], "medium")).toBe(true);
    expect(shouldFail([pkg("low", true)], "critical")).toBe(true);
    expect(shouldFail([pkg(null)], "low")).toBe(false);
    expect(shouldFail([pkg("CRITICAL", true)], "none")).toBe(false);
  });
});
