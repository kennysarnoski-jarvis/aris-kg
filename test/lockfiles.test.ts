import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  parseCargoLock,
  parseGoMod,
  parsePackageLock,
  parsePnpmLock,
  parsePoetryLock,
  parseRequirements,
  parseYarnLock,
  readLockfiles,
} from "../src/lockfiles.js";

describe("lockfile parsers", () => {
  it("reads package-lock v3 paths, including nested and scoped packages, and skips links", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/express": { version: "4.16.2" },
        "node_modules/@babel/core": { version: "7.24.0" },
        "node_modules/express/node_modules/qs": { version: "6.5.1" },
        "node_modules/local-thing": { link: true },
      },
    });
    expect(parsePackageLock(lock)).toEqual([
      { name: "express", version: "4.16.2", ecosystem: "npm" },
      { name: "@babel/core", version: "7.24.0", ecosystem: "npm" },
      { name: "qs", version: "6.5.1", ecosystem: "npm" },
    ]);
  });

  it("reads package-lock v1 nested dependencies", () => {
    const lock = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { lodash: { version: "4.17.20", dependencies: { minimist: { version: "0.0.8" } } } },
    });
    expect(parsePackageLock(lock).map((d) => `${d.name}@${d.version}`)).toEqual(["lodash@4.17.20", "minimist@0.0.8"]);
  });

  it("reads yarn v1 and berry entries", () => {
    const lock = [
      "# yarn lockfile v1",
      "",
      '"@babel/core@^7.0.0", "@babel/core@^7.1.0":',
      '  version "7.24.0"',
      "",
      "lodash@^4.17.0:",
      '  version "4.17.20"',
      "",
      '"left-pad@npm:^1.3.0":',
      "  version: 1.3.0",
    ].join("\n");
    expect(parseYarnLock(lock).map((d) => `${d.name}@${d.version}`)).toEqual([
      "@babel/core@7.24.0",
      "lodash@4.17.20",
      "left-pad@1.3.0",
    ]);
  });

  it("reads pnpm v6 and v9 package keys", () => {
    const lock = [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      lodash:",
      "        version: 4.17.21",
      "packages:",
      "  /express@4.16.2:",
      "    resolution: {integrity: sha512-x}",
      "  lodash@4.17.21:",
      "    resolution: {integrity: sha512-y}",
      "  '@babel/core@7.24.0':",
      "    resolution: {integrity: sha512-z}",
      "  react-dom@18.3.1(react@18.3.1):",
      "    resolution: {integrity: sha512-w}",
      "snapshots:",
      "  lodash@4.17.21: {}",
    ].join("\n");
    expect(parsePnpmLock(lock).map((d) => `${d.name}@${d.version}`)).toEqual([
      "express@4.16.2",
      "lodash@4.17.21",
      "@babel/core@7.24.0",
      "react-dom@18.3.1",
    ]);
  });

  it("reads pinned requirements and skips ranges, comments and options", () => {
    const text = [
      "# web",
      "Django==3.2.0  # pinned",
      "requests[security]==2.19.1",
      "flask>=2.0",
      "-r other.txt",
      "urllib3 === 1.24.1 ; python_version >= '3'",
    ].join("\n");
    expect(parseRequirements(text).map((d) => `${d.name}@${d.version}`)).toEqual([
      "Django@3.2.0",
      "requests@2.19.1",
      "urllib3@1.24.1",
    ]);
  });

  it("reads poetry.lock and Cargo.lock packages", () => {
    const toml = '[[package]]\nname = "jinja2"\nversion = "2.10"\n\n[[package]]\nname = "serde"\nversion = "1.0.100"\n';
    expect(parsePoetryLock(toml)).toEqual([
      { name: "jinja2", version: "2.10", ecosystem: "pypi" },
      { name: "serde", version: "1.0.100", ecosystem: "pypi" },
    ]);
    expect(parseCargoLock(toml)[1]).toEqual({ name: "serde", version: "1.0.100", ecosystem: "crates" });
  });

  it("reads go.mod require lines and blocks", () => {
    const text = [
      "module example.com/app",
      "go 1.22",
      "require github.com/gin-gonic/gin v1.6.0",
      "require (",
      "\tgolang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975 // indirect",
      "\tgithub.com/pkg/errors v0.9.1",
      ")",
    ].join("\n");
    expect(parseGoMod(text).map((d) => `${d.name}@${d.version}`)).toEqual([
      "github.com/gin-gonic/gin@v1.6.0",
      "golang.org/x/crypto@v0.0.0-20200220183623-bac4c82f6975",
      "github.com/pkg/errors@v0.9.1",
    ]);
  });

  it("finds lockfiles in a folder and de-duplicates packages", () => {
    const dir = mkdtempSync(join(tmpdir(), "aris-kg-"));
    writeFileSync(join(dir, "requirements.txt"), "Django==3.2.0\nDjango==3.2.0\n");
    writeFileSync(join(dir, "go.mod"), "module x\nrequire github.com/pkg/errors v0.9.1\n");
    expect(readLockfiles(dir)).toEqual([
      { file: "requirements.txt", dependencies: [{ name: "Django", version: "3.2.0", ecosystem: "pypi" }] },
      { file: "go.mod", dependencies: [{ name: "github.com/pkg/errors", version: "v0.9.1", ecosystem: "go" }] },
    ]);
  });
});
