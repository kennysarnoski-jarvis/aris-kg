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

const LOCKFILES: [string, Parser][] = [
  ["package-lock.json", parsePackageLock],
  ["pnpm-lock.yaml", parsePnpmLock],
  ["yarn.lock", parseYarnLock],
  ["poetry.lock", parsePoetryLock],
  ["requirements.txt", parseRequirements],
  ["Cargo.lock", parseCargoLock],
  ["go.mod", parseGoMod],
];

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
