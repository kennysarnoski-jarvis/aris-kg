import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  parseCargoLock,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGradleLockfile,
  parseMixLock,
  parseNugetLock,
  parsePackageLock,
  parsePackageResolved,
  parsePipfileLock,
  parsePnpmLock,
  parsePoetryLock,
  parsePubspecLock,
  parseRequirements,
  parseUvLock,
  parseYarnLock,
  readLockfiles,
} from "../src/lockfiles.js";

const short = (deps: { name: string; version: string; ecosystem?: string }[]) =>
  deps.map((d) => `${d.ecosystem}:${d.name}@${d.version}`);

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

  it("reads uv.lock and Pipfile.lock, skipping the project itself", () => {
    const uv = [
      "version = 1",
      "[[package]]",
      'name = "my-app"',
      'version = "0.1.0"',
      'source = { editable = "." }',
      "",
      "[[package]]",
      'name = "jinja2"',
      'version = "2.10"',
      'source = { registry = "https://pypi.org/simple" }',
    ].join("\n");
    expect(short(parseUvLock(uv))).toEqual(["pypi:jinja2@2.10"]);
    const pipfile = JSON.stringify({
      _meta: {},
      default: { requests: { version: "==2.19.0" }, local: { path: "." } },
      develop: { pytest: { version: "==7.0.0" } },
    });
    expect(short(parsePipfileLock(pipfile))).toEqual(["pypi:requests@2.19.0", "pypi:pytest@7.0.0"]);
  });

  it("reads Gemfile.lock GEM specs, dropping platform suffixes and requirement lines", () => {
    const text = [
      "GIT",
      "  remote: https://github.com/x/y.git",
      "  specs:",
      "    forked (1.0.0)",
      "",
      "GEM",
      "  remote: https://rubygems.org/",
      "  specs:",
      "    actionpack (6.1.7.3)",
      "      rack (~> 2.0, >= 2.0.9)",
      "    nokogiri (1.15.4-x86_64-linux)",
      "    rack (2.2.6)",
      "",
      "PLATFORMS",
      "  x86_64-linux",
    ].join("\n");
    expect(short(parseGemfileLock(text))).toEqual([
      "rubygems:actionpack@6.1.7.3",
      "rubygems:nokogiri@1.15.4",
      "rubygems:rack@2.2.6",
    ]);
  });

  it("reads composer.lock packages and dev packages, skipping dev branches", () => {
    const text = JSON.stringify({
      packages: [
        { name: "symfony/http-kernel", version: "v4.4.0" },
        { name: "acme/fork", version: "dev-main" },
      ],
      "packages-dev": [{ name: "phpunit/phpunit", version: "9.5.0" }],
    });
    expect(short(parseComposerLock(text))).toEqual(["packagist:symfony/http-kernel@4.4.0", "packagist:phpunit/phpunit@9.5.0"]);
  });

  it("reads NuGet packages.lock.json across frameworks, skipping project references", () => {
    const text = JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          "Newtonsoft.Json": { type: "Direct", requested: "[12.0.1, )", resolved: "12.0.1" },
          "My.Library": { type: "Project" },
        },
        "net6.0": { "System.Text.Json": { type: "Transitive", resolved: "6.0.0" } },
      },
    });
    expect(short(parseNugetLock(text))).toEqual(["nuget:Newtonsoft.Json@12.0.1", "nuget:System.Text.Json@6.0.0"]);
  });

  it("reads pubspec.lock hosted packages and skips SDK packages", () => {
    const text = [
      "packages:",
      "  http:",
      '    dependency: "direct main"',
      "    description:",
      '      name: http',
      '      url: "https://pub.dev"',
      "    source: hosted",
      '    version: "0.13.5"',
      "  flutter:",
      '    dependency: "direct main"',
      "    description: flutter",
      "    source: sdk",
      '    version: "0.0.0"',
      "sdks:",
      '  dart: ">=3.0.0 <4.0.0"',
    ].join("\n");
    expect(short(parsePubspecLock(text))).toEqual(["pub:http@0.13.5"]);
  });

  it("reads mix.lock hex packages by their hex name", () => {
    const text = [
      "%{",
      '  "phoenix": {:hex, :phoenix, "1.7.10", "abc", [:mix], [], "hexpm", "def"},',
      '  "plug_crypto": {:hex, :plug_crypto, "1.2.3", "abc", [:mix], [], "hexpm", "def"},',
      '  "dep_from_git": {:git, "https://github.com/x/y.git", "abc", []},',
      "}",
    ].join("\n");
    expect(short(parseMixLock(text))).toEqual(["hex:phoenix@1.7.10", "hex:plug_crypto@1.2.3"]);
  });

  it("reads Package.resolved v1 and v2 pins as github.com/owner/repo", () => {
    const v2 = JSON.stringify({
      pins: [
        { identity: "vapor", location: "https://github.com/vapor/vapor.git", state: { version: "4.50.0" } },
        { identity: "branchy", location: "https://github.com/x/branchy", state: { branch: "main", version: null } },
      ],
      version: 2,
    });
    const v1 = JSON.stringify({
      object: { pins: [{ package: "NIO", repositoryURL: "git@github.com:apple/swift-nio.git", state: { version: "2.40.0" } }] },
      version: 1,
    });
    expect(short(parsePackageResolved(v2))).toEqual(["swift:github.com/vapor/vapor@4.50.0"]);
    expect(short(parsePackageResolved(v1))).toEqual(["swift:github.com/apple/swift-nio@2.40.0"]);
  });

  it("reads gradle.lockfile coordinates as group:artifact", () => {
    const text = [
      "# This is a Gradle generated file for dependency locking.",
      "com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath",
      "org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath",
      "empty=annotationProcessor",
    ].join("\n");
    expect(short(parseGradleLockfile(text))).toEqual([
      "maven:com.fasterxml.jackson.core:jackson-databind@2.9.8",
      "maven:org.apache.logging.log4j:log4j-core@2.14.1",
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
