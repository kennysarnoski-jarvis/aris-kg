// Client for the Aris knowledge graph API at youraris.com.
// Every call is billed to the account behind the API key.

export const DEFAULT_BASE_URL = "https://youraris.com";
const DEPENDENCY_BATCH = 500;
const MAX_DESCRIPTION = 1500;

export type SearchKind = "cve" | "knowledge" | "code";
export const ECOSYSTEMS = ["npm", "pypi", "crates", "maven", "go"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export interface Dependency {
  name: string;
  version: string;
  ecosystem?: Ecosystem;
}

export interface SearchResult {
  query: string;
  results: { label: string; category: string; score: number; description: string }[];
}

export interface WebSearchResult {
  query: string;
  summary: string;
  results: { title: string; url: string; snippet: string }[];
}

export interface Vulnerability {
  id: string | null;
  severity: string | null;
  cvssScore: number | null;
  affectedVersions: string[];
  fixedIn: string[];
  exploitedInTheWild: boolean;
  fixCommitUrl: string | null;
  summary: string;
}

export interface PackageReport {
  name: string;
  version: string;
  ecosystem: string | null;
  vulnerabilities: Vulnerability[];
  possibleMatches: { id: string | null; severity: string | null; summary: string }[];
}

export interface DependencyReport {
  packages: PackageReport[];
  costCents: number;
}

export class ArisError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ArisError";
  }
}

export interface ArisClientOptions {
  apiKey: string;
  baseUrl?: string;
  fetch?: typeof fetch;
}

function clip(text: string | null | undefined, max = MAX_DESCRIPTION): string {
  const flat = (text ?? "").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

const HINTS: Record<number, string> = {
  401: "Your Aris API key was refused. Create one on youraris.com/account and set ARIS_API_KEY.",
  402: "Your Aris balance is too low for this call. Add credits on youraris.com/account.",
  429: "Too many Aris calls this minute. Try again shortly.",
};

export class ArisClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ArisClientOptions) {
    if (!options.apiKey?.trim()) {
      throw new ArisError(HINTS[401]!, 401);
    }
    this.apiKey = options.apiKey.trim();
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? fetch;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        "User-Agent": "aris-kg",
      },
    });
    if (!response.ok) {
      let detail = "";
      try {
        const body = (await response.json()) as { detail?: unknown };
        detail = typeof body.detail === "string" ? body.detail : "";
      } catch {
        // Not JSON; the hint or status says enough.
      }
      const hint = HINTS[response.status];
      const message = detail && hint && response.status === 401 ? `${detail}. ${hint}` : detail || hint;
      throw new ArisError(message || `Aris API error ${response.status}`, response.status);
    }
    return (await response.json()) as T;
  }

  async search(kind: SearchKind, query: string, limit = 10): Promise<SearchResult> {
    const params = new URLSearchParams({ query, limit: String(limit) });
    const body = await this.request<{
      query: string;
      results: { label: string; category: string; score: number; description?: string | null }[];
    }>(`/api/local/search/${kind}?${params}`);
    return {
      query: body.query,
      results: body.results.map((result) => ({
        label: result.label,
        category: result.category,
        score: Math.round(result.score * 1000) / 1000,
        description: clip(result.description),
      })),
    };
  }

  async webSearch(query: string): Promise<WebSearchResult> {
    const body = await this.request<{
      query: string;
      summary?: string | null;
      results: { title: string; url: string; snippet?: string | null }[];
    }>("/api/local/web_search", { method: "POST", body: JSON.stringify({ query }) });
    return {
      query: body.query,
      summary: clip(body.summary, 4000),
      results: body.results.map((result) => ({
        title: result.title,
        url: result.url,
        snippet: clip(result.snippet, 400),
      })),
    };
  }

  async checkDependencies(dependencies: Dependency[]): Promise<DependencyReport> {
    const report: DependencyReport = { packages: [], costCents: 0 };
    for (let start = 0; start < dependencies.length; start += DEPENDENCY_BATCH) {
      const batch = dependencies.slice(start, start + DEPENDENCY_BATCH);
      const body = await this.request<RawBatch>("/api/local/quarry/cve_batch", {
        method: "POST",
        body: JSON.stringify({
          packages: batch.map((dep) => ({
            name: dep.name,
            version: dep.version,
            ...(dep.ecosystem ? { ecosystem: dep.ecosystem } : {}),
          })),
        }),
      });
      report.costCents += body.billed_cents ?? 0;
      for (const result of body.results) {
        report.packages.push({
          name: result.name,
          version: result.version,
          ecosystem: result.ecosystem ?? null,
          vulnerabilities: result.cves.map((cve) => ({
            id: cve.id ?? null,
            severity: cve.severity ?? null,
            cvssScore: cve.cvss_score ?? null,
            affectedVersions: cve.affected_versions ?? [],
            fixedIn: cve.fixed_in ?? [],
            exploitedInTheWild: cve.exploit_available === true,
            fixCommitUrl: cve.fix_commit_url ?? null,
            summary: clip(cve.summary),
          })),
          possibleMatches: (result.name_similar ?? []).map((match) => ({
            id: match.id ?? null,
            severity: match.severity ?? null,
            summary: clip(match.summary, 400),
          })),
        });
      }
    }
    return report;
  }
}

interface RawBatch {
  results: {
    name: string;
    version: string;
    ecosystem?: string | null;
    cves: {
      id?: string | null;
      severity?: string | null;
      summary?: string | null;
      cvss_score?: number | null;
      affected_versions?: string[] | null;
      fixed_in?: string[] | null;
      fix_commit_url?: string | null;
      exploit_available?: boolean | null;
    }[];
    name_similar?: { id?: string | null; severity?: string | null; summary?: string | null }[] | null;
  }[];
  billed_cents?: number | null;
}
