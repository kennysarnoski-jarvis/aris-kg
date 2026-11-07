# aris-kg

Coding agents answer from training data that stops months before you use them. `aris-kg` connects
them to the Aris knowledge graph instead: more than 15 million concepts, refreshed daily from NVD,
OSV, GitHub security advisories, MITRE ATT&CK, OWASP and framework releases.

It comes three ways:

- **An MCP server** for Claude Code, Cursor, Codex, Windsurf and any other MCP client.
- **A CLI** that checks every pinned version in your lockfiles against known CVEs.
- **A GitHub Action** that fails a pull request when it adds a vulnerable dependency.

The code is open source (MIT). The graph is a paid API: you need a key from
[youraris.com/account](https://youraris.com/account), and each call is billed to your Aris credits.

| Call | Price |
| --- | --- |
| CVE, knowledge or code search | 1¢ |
| Dependency check | 1¢ per package |
| Web search | 2¢ |

Every account is limited to 120 calls a minute.

## MCP server

The server gives your agent five tools, and tells it to use them without being asked: before
adding a dependency, for any CVE, when picking a library version, and before writing auth,
crypto, SQL or file-path code.

| Tool | What it does |
| --- | --- |
| `aris_check_dependencies` | Checks exact package versions: CVE ids, severity, CVSS, affected and fixed versions, and whether a CVE is exploited in the wild |
| `aris_search_cve` | Finds CVEs and GitHub advisories by id or description |
| `aris_search_knowledge` | Current major versions and setup patterns, attack techniques, mitigations and known pitfalls |
| `aris_search_code` | Reference code from published packages |
| `aris_web_search` | Anything newer than the graph, with source URLs |

### Claude Code

```bash
claude mcp add aris -e ARIS_API_KEY=your-key -- npx -y aris-kg mcp
```

### Cursor, Windsurf and other JSON-configured clients

```json
{
  "mcpServers": {
    "aris": {
      "command": "npx",
      "args": ["-y", "aris-kg", "mcp"],
      "env": { "ARIS_API_KEY": "your-key" }
    }
  }
}
```

### Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.aris]
command = "npx"
args = ["-y", "aris-kg", "mcp"]
env = { ARIS_API_KEY = "your-key" }
```

## CLI

```bash
export ARIS_API_KEY=your-key

npx aris-kg audit                   # lockfiles in the current folder
npx aris-kg audit ./service --fail-on critical
npx aris-kg audit --json > report.json
npx aris-kg search cve CVE-2024-3094
```

`audit` reads `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `requirements.txt`
(pinned `==` lines), `Cargo.lock` and `go.mod`. It only checks exact versions, so use a lockfile
rather than a manifest with ranges.

It exits with `1` when a vulnerability is at or above `--fail-on` (default `high`), or is exploited in
the wild at any severity. `--fail-on none` never fails. Errors exit with `2`.

## GitHub Action

```yaml
name: Dependency audit
on: [pull_request]
jobs:
  aris:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kennysarnoski-jarvis/aris-kg@v0
        with:
          api-key: ${{ secrets.ARIS_API_KEY }}
          fail-on: high
```

## As a library

```ts
import { ArisClient } from "aris-kg";

const aris = new ArisClient({ apiKey: process.env.ARIS_API_KEY! });
const report = await aris.checkDependencies([{ name: "lodash", version: "4.17.20", ecosystem: "npm" }]);
```

## Development

```bash
npm install
npm test
npm run build
node dist/bin.js --help
```

Set `ARIS_BASE_URL` to point the client at another server.

## License

MIT
