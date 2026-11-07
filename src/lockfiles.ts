// Reads exact dependency versions from lockfiles. Ranges can't be checked
// against CVE data, so only pinned versions are returned.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { Dependency, Ecosystem } from "./client.js";

export interface LockfileResult {
  file: string;
  dependencies: Dependency[];
}

type Parser = (text: string) => Dependency[];

const EXACT = /^\d[\w.+-]*$/;

function dep(name: string, version: string, ecosystem: Ecosystem): Dependency | null {
  const cleanName = name.trim();
  const cleanVersion = version.trim().replace(/^v(?=\d)/, ecosystem === "go" ? "v" : "");
  if (!cleanName || !EXACT.test(cleanVersion.replace(/^v/, ""))) return null;
  return { name: cleanName, version: cleanVersion, ecosystem };
}

export const parsePackageLock: Parser = (text) => {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; link?: boolean }>;
    dependencies?: Record<string, { version?: string; dependencies?: unknown }>;
  };
  const out: Dependency[] = [];
  if (lock.packages) {
    for (const [path, info] of Object.entries(lock.packages)) {
      if (!path || info.link || !info.version) continue;
      const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      const found = dep(name, info.version, "npm");
      if (found) out.push(found);
    }
    return out;
  }
  // lockfileVersion 1: nested dependencies
  const walk = (deps: Record<string, { version?: string; dependencies?: unknown }> | undefined) => {
    for (const [name, info] of Object.entries(deps ?? {})) {
      const found = info.version ? dep(name, info.version, "npm") : null;
      if (found) out.push(found);
      walk(info.dependencies as typeof deps);
    }
  };
  walk(lock.dependencies);
  return out;
};

export const parseYarnLock: Parser = (text) => {
  const out: Dependency[] = [];
  let names: string[] = [];
  for (const line of text.split("\n")) {
    if (/^\S/.test(line) && line.trim().endsWith(":") && !line.startsWith("#")) {
      // "lodash@^4.17.0", "@babel/core@^7.0.0":  or  "lodash@npm:^4.17.0":
      names = line
        .slice(0, -1)
        .split(",")
        .map((spec) => spec.trim().replace(/^"|"$/g, ""))
        .map((spec) => spec.slice(0, spec.indexOf("@", 1)));
    } else {
      const match = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
      if (match && names.length > 0) {
        const found = dep(names[0]!, match[1]!, "npm");
        if (found) out.push(found);
        names = [];
      }
    }
  }
  return out;
};

export const parsePnpmLock: Parser = (text) => {
  const out: Dependency[] = [];
  let inPackages = false;
  for (const line of text.split("\n")) {
    if (/^\S/.test(line)) inPackages = line.startsWith("packages:");
    if (!inPackages) continue;
    // v6+: "  /lodash@4.17.21:"  v9: "  lodash@4.17.21:"  scoped: "  '@babel/core@7.24.0':"
    const match = /^ {2}'?\/?((?:@[^@/'\s]+\/)?[^@/'\s(]+)@([^('\s:]+)/.exec(line);
    if (match) {
      const found = dep(match[1]!, match[2]!, "npm");
      if (found) out.push(found);
    }
  }
  return out;
};

export const parseRequirements: Parser = (text) => {
  const out: Dependency[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.split("#")[0]!.trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/.exec(line);
    if (match) {
      const found = dep(match[1]!, match[2]!, "pypi");
      if (found) out.push(found);
    }
  }
  return out;
};

function tomlPackages(text: string, ecosystem: Ecosystem): Dependency[] {
  const out: Dependency[] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const found = name && version ? dep(name, version, ecosystem) : null;
    if (found) out.push(found);
  }
  return out;
}

export const parsePoetryLock: Parser = (text) => tomlPackages(text, "pypi");
// uv.lock lists the project itself as an editable or virtual package; skip it.
export const parseUvLock: Parser = (text) =>
  tomlPackages(
    text
      .split(/^(?=\[\[package\]\]\s*$)/m)
      .filter((block) => !/^source\s*=\s*\{\s*(editable|virtual)\s*=/m.test(block))
      .join(""),
    "pypi",
  );

export const parsePipfileLock: Parser = (text) => {
  const lock = JSON.parse(text) as Record<string, Record<string, { version?: string }> | undefined>;
  const out: Dependency[] = [];
  for (const section of ["default", "develop"]) {
    for (const [name, info] of Object.entries(lock[section] ?? {})) {
      const version = info?.version?.replace(/^===?/, "");
      const found = version ? dep(name, version, "pypi") : null;
      if (found) out.push(found);
    }
  }
  return out;
};
export const parseCargoLock: Parser = (text) => tomlPackages(text, "crates");

export const parseGoMod: Parser = (text) => {
  const out: Dependency[] = [];
  let inBlock = false;
  for (const raw of text.split("\n")) {
    const line = raw.split("//")[0]!.trim();
    if (line.startsWith("require (")) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      continue;
    }
    const spec = inBlock ? line : line.startsWith("require ") ? line.slice("require ".length).trim() : "";
    const match = /^(\S+)\s+(v\S+)$/.exec(spec);
    if (match) {
      const found = dep(match[1]!, match[2]!, "go");
      if (found) out.push(found);
    }
  }
  return out;
};

export const parseGemfileLock: Parser = (text) => {
  const out: Dependency[] = [];
  let inGem = false;
  for (const line of text.split("\n")) {
    if (/^\S/.test(line)) inGem = line.trim() === "GEM";
    if (!inGem) continue;
    // "    rails (7.0.4)" or "    nokogiri (1.15.4-x86_64-linux)"; deeper lines are requirements.
    const match = /^ {4}([^\s(]+) \(([^)\s]+)\)$/.exec(line);
    if (match) {
      const found = dep(match[1]!, match[2]!.split("-")[0]!, "rubygems");
      if (found) out.push(found);
    }
  }
  return out;
};

export const parseComposerLock: Parser = (text) => {
  const lock = JSON.parse(text) as Record<string, { name?: string; version?: string }[] | undefined>;
  const out: Dependency[] = [];
  for (const pkg of [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])]) {
    const found = pkg.name && pkg.version ? dep(pkg.name, pkg.version, "packagist") : null;
    if (found) out.push(found);
  }
  return out;
};

export const parseNugetLock: Parser = (text) => {
  const lock = JSON.parse(text) as {
    dependencies?: Record<string, Record<string, { type?: string; resolved?: string }>>;
  };
  const out: Dependency[] = [];
  for (const framework of Object.values(lock.dependencies ?? {})) {
    for (const [name, info] of Object.entries(framework)) {
      if (info.type === "Project" || !info.resolved) continue;
      const found = dep(name, info.resolved, "nuget");
      if (found) out.push(found);
    }
  }
  return out;
};

export const parsePubspecLock: Parser = (text) => {
  const out: Dependency[] = [];
  let inPackages = false;
  let name = "";
  let source = "";
  for (const line of text.split("\n")) {
    if (/^\S/.test(line)) inPackages = line.startsWith("packages:");
    if (!inPackages) continue;
    const pkg = /^ {2}([^\s:]+):\s*$/.exec(line);
    if (pkg) {
      name = pkg[1]!;
      source = "";
      continue;
    }
    const src = /^ {4}source:\s*(\S+)/.exec(line);
    if (src) source = src[1]!;
    const version = /^ {4}version:\s*"?([^"\s]+)"?/.exec(line);
    // SDK packages (flutter, flutter_test) aren't published on pub.dev.
    if (version && name && source !== "sdk") {
      const found = dep(name, version[1]!, "pub");
      if (found) out.push(found);
    }
  }
  return out;
};

export const parseMixLock: Parser = (text) => {
  const out: Dependency[] = [];
  for (const line of text.split("\n")) {
    // "phoenix": {:hex, :phoenix, "1.7.10", "sha", [:mix], [...], "hexpm", "sha"},
    const match = /^\s*"[^"]+":\s*\{:hex,\s*:"?([\w.-]+)"?,\s*"([^"]+)"/.exec(line);
    if (match) {
      const found = dep(match[1]!, match[2]!, "hex");
      if (found) out.push(found);
    }
  }
  return out;
};

/** github.com/owner/repo, the package name OSV uses for Swift. */
function swiftName(location: string): string {
  return location
    .trim()
    .replace(/^git@([^:]+):/, "$1/")
    .replace(/^[a-z+]+:\/\//i, "")
    .replace(/\.git$/, "")
    .replace(/\/+$/, "");
}

export const parsePackageResolved: Parser = (text) => {
  const lock = JSON.parse(text) as {
    pins?: { location?: string; state?: { version?: string | null } }[];
    object?: { pins?: { repositoryURL?: string; state?: { version?: string | null } }[] };
  };
  const pins = [
    ...(lock.pins ?? []).map((p) => ({ url: p.location, version: p.state?.version })),
    ...(lock.object?.pins ?? []).map((p) => ({ url: p.repositoryURL, version: p.state?.version })),
  ];
  const out: Dependency[] = [];
  for (const pin of pins) {
    const found = pin.url && pin.version ? dep(swiftName(pin.url), pin.version, "swift") : null;
    if (found) out.push(found);
  }
  return out;
};

export const parseGradleLockfile: Parser = (text) => {
  const out: Dependency[] = [];
  for (const raw of text.split("\n")) {
    // com.fasterxml.jackson.core:jackson-databind:2.13.0=compileClasspath,runtimeClasspath
    const match = /^([^#\s:=]+):([^:=\s]+):([^:=\s]+)=/.exec(raw.trim());
    if (match) {
      const found = dep(`${match[1]}:${match[2]}`, match[3]!, "maven");
      if (found) out.push(found);
    }
  }
  return out;
};

const LOCKFILES: [string, Parser][] = [
  ["package-lock.json", parsePackageLock],
  ["pnpm-lock.yaml", parsePnpmLock],
  ["yarn.lock", parseYarnLock],
  ["poetry.lock", parsePoetryLock],
  ["uv.lock", parseUvLock],
  ["Pipfile.lock", parsePipfileLock],
  ["requirements.txt", parseRequirements],
  ["Cargo.lock", parseCargoLock],
  ["go.mod", parseGoMod],
  ["gradle.lockfile", parseGradleLockfile],
  ["Gemfile.lock", parseGemfileLock],
  ["composer.lock", parseComposerLock],
  ["packages.lock.json", parseNugetLock],
  ["mix.lock", parseMixLock],
  ["pubspec.lock", parsePubspecLock],
  ["Package.resolved", parsePackageResolved],
];

export const LOCKFILE_NAMES = LOCKFILES.map(([file]) => file);

/** Lockfiles found in a directory, each with its unique pinned dependencies. */
export function readLockfiles(directory: string): LockfileResult[] {
  const results: LockfileResult[] = [];
  for (const [file, parse] of LOCKFILES) {
    const path = join(directory, file);
    if (!existsSync(path)) continue;
    const seen = new Set<string>();
    const dependencies = parse(readFileSync(path, "utf8")).filter((d) => {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    results.push({ file, dependencies });
  }
  return results;
}
