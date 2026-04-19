<h1 align="center">oy</h1>

<div align="center">
  <strong>Policy-based security scanning for AI agent files</strong>
</div>
<div align="center">
  Scan Skills, Commands, Agent specs, and Agent.md files for malicious instructions before they reach your agent
</div>

<br />

<div align="center">
  <!-- Go version -->
  <a href="https://golang.org/dl/">
    <img src="https://img.shields.io/badge/go-1.21+-blue.svg?style=flat-square"
      alt="Go version" />
  </a>
  <!-- License -->
  <a href="https://github.com/aljoshare/oy/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square"
      alt="MIT license" />
  </a>
  <!-- OPA -->
  <a href="https://www.openpolicyagent.org/">
    <img src="https://img.shields.io/badge/policies-OPA%20Rego-blueviolet.svg?style=flat-square"
      alt="OPA Rego policies" />
  </a>
  <!-- Docker -->
  <a href="https://github.com/aljoshare/oy/pkgs/container/oy">
    <img src="https://img.shields.io/badge/container-ghcr.io-0db7ed.svg?style=flat-square"
      alt="Container image" />
  </a>
  <!-- Scorecard -->
  <a href="https://scorecard.dev/viewer/?uri=github.com/aljoshare/oy">
    <img src="https://api.scorecard.dev/projects/github.com/aljoshare/oy/badge"
      alt="OpenSSF Scorecard" />
  </a>
  <!-- Status -->
  <img src="https://img.shields.io/badge/status-unfinished--goods-yellow.svg?style=flat-square"
    alt="unfinished-goods" />
</div>

<div align="center">
  <h3>
    <a href="https://github.com/aljoshare/oy-policies">
      Policies
    </a>
    <span> | </span>
    <a href="#installation">
      Install
    </a>
    <span> | </span>
    <a href="#usage">
      Usage
    </a>
    <span> | </span>
    <a href="#custom-policies">
      Custom policies
    </a>
    <span> | </span>
    <a href="#ci-integration">
      CI
    </a>
  </h3>
</div>

<div align="center">
  <img src="demo.gif" alt="oy demo" />
</div>

## Table of Contents
- [Features](#features)
- [Example](#example)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Ignoring files](#ignoring-files)
- [Policies](#policies)
- [Custom policies](#custom-policies)
- [CI integration](#ci-integration)
- [Troubleshooting](#troubleshooting)


## Features
- __agent-focused:__ built to scan Skills, Commands, Agent specs, and `AGENT.md` / `CLAUDE.md` files
- __OPA-powered:__ policies are plain Rego — readable, testable, and composable
- __extensible:__ drop in any Git-hosted or local policy repository with one command
- __CI-ready:__ exits `1` on violations, `0` on clean — binary, container, or `go install`
- __multi-platform container:__ `linux/amd64` and `linux/arm64` images on `ghcr.io`, built on Chainguard

## Example

```bash
oy repo add github.com/aljoshare/oy-policies

# Scan all Skills and Commands
oy scan .claude/

# Scan root-level agent instruction files
oy scan CLAUDE.md
oy scan AGENT.md
```

Output when violations are found:

```
FAIL .claude/skills/assistant/SKILL.md
  - possible prompt injection: "ignore previous instructions"
  - tool invocation abuse: bash tool

2 file(s) scanned, 2 violation(s) found
```

## Installation

**Container (recommended for CI)**

```bash
nerdctl pull ghcr.io/aljoshare/oy:latest
```

Supports `linux/amd64` and `linux/arm64`. Built on [Chainguard](https://www.chainguard.dev/) — minimal attack surface, runs as nonroot.

**Go install**

```bash
go install github.com/aljoshare/oy@latest
```

**Build from source**

```bash
git clone https://github.com/aljoshare/oy
cd oy
go build -o oy .
```

**Requirements (binary only):** Go 1.21+, `git` (used by `oy repo add` to clone policy repos).

## Usage

### Scanning

```bash
oy scan <path>
```

`<path>` can be a single `.md` file or a directory. Directories are walked recursively — so pointing `oy` at `.claude/` scans all Skills and Commands in one shot.

```bash
# Scan all Skills and Commands under .claude/
oy scan .claude/

# Scan a single CLAUDE.md or AGENT.md
oy scan CLAUDE.md

# Use a local policy directory instead of registered repos
oy scan .claude/ --policies ./my-policies

# Output as JSON (useful for CI / downstream tooling)
oy scan .claude/ --format json
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--policies` | `-p` | — | Directory of `.rego` files to use instead of registered repos |
| `--format` | `-f` | `text` | Output format: `text` or `json` |

| Exit code | Meaning |
|---|---|
| `0` | No violations found |
| `1` | One or more violations found (or a fatal error occurred) |

### Listing loaded rules

```bash
oy list
```

Lists every rule that is active in the loaded policy set, sorted alphabetically. Rules without a `# METADATA` title are excluded — `oy` will also print a warning to stderr for each such rule when scanning.

```bash
# List rules from a local policy directory
oy list --policies ./my-policies

# Output as JSON
oy list --format json
```

Example output:

```
  - Data Exfiltration Instructions
    Detects instructions to read sensitive files (SSH keys, AWS credentials, .env) and transmit them via HTTP, DNS, or image URLs.
  - Instruction Override
    Detects indirect prompt injection via instruction override patterns such as "ignore previous instructions" or "admin mode activated".
  ...

14 rule(s) loaded
```

| Flag | Short | Default | Description |
|---|---|---|---|
| `--policies` | `-p` | — | Directory of `.rego` files to use instead of registered repos |
| `--format` | `-f` | `text` | Output format: `text` or `json` |

### Managing policy repositories

```bash
# Register a policy repository (cloned into the OS cache directory)
oy repo add github.com/aljoshare/oy-policies

# List registered repositories and their local cache paths
oy repo list
```

`oy repo add` accepts bare `host/owner/repo` references as well as full `https://` and `git@` URLs. Config is stored in your OS user config directory (`~/.config/oy/config.json` on Linux, `~/Library/Application Support/oy/config.json` on macOS).

To update a registered repository, run `git pull` in its cache directory, which `oy repo list` will show you.

## Output

**Text (default) — violations found**

```
FAIL .claude/skills/assistant/SKILL.md
  - possible prompt injection: "ignore previous instructions"
  - potentially destructive shell command: "rm -rf /"

2 file(s) scanned, 2 violation(s) found
```

**Text — clean**

```
OK: 3 file(s) scanned, no violations found
```

**JSON**

```json
{
  "files_scanned": 2,
  "violations": [
    {
      "file": ".claude/skills/assistant/SKILL.md",
      "message": "possible prompt injection: \"ignore previous instructions\""
    }
  ]
}
```

## Ignoring files

Create a `.oyignore` file in the root directory being scanned to exclude files from evaluation. Patterns follow the same syntax as [`filepath.Match`](https://pkg.go.dev/path/filepath#Match) — glob wildcards are supported, and lines starting with `#` are treated as comments.

```
# .oyignore
vendor/AGENT.md
*.generated.md
docs/*.md
```

Files matched by `.oyignore` are skipped silently. If all files in a directory are ignored, `oy scan` exits `0` with no output.

## Policies

Policies are maintained in separate repositories and registered with `oy repo add`. The official collection is [aljoshare/oy-policies](https://github.com/aljoshare/oy-policies):

| Policy file | Detects |
|---|---|
| `prompt_injection.rego` | Instruction overrides, context/memory poisoning, invisible Unicode injection |
| `jailbreak.rego` | DAN/AIM/BISH/STAN personas, safety bypass framing, hypothetical/fictional framing, FlipAttack |
| `harmful_commands.rego` | Destructive shell commands, privilege escalation, persistence attacks, supply chain attacks |
| `exfiltration.rego` | Sensitive file reads, credential/key exposure, env var dumping, pipe-to-shell, image-URL exfiltration |
| `social_engineering.rego` | Phishing patterns, agent-targeted urgency/authority framing, false-context misdirection |
| `tool_poisoning.rego` | Tool/skill invocation abuse, MCP tool poisoning via hidden HTML comments |

See the [oy-policies repository](https://github.com/aljoshare/oy-policies) for full descriptions and source citations.

## Custom policies

Policies are plain [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) files. All rules must belong to `package oy` and express violations as `deny` set entries. Each rule must have a `# METADATA` block with at least a `title` — rules without one are skipped during scanning and a warning is printed to stderr.

```rego
package oy

import rego.v1

# METADATA
# title: My Custom Rule
# description: Detects my forbidden phrase in agent files.
deny contains msg if {
    contains(lower(input.content), "my forbidden phrase")
    msg := "found forbidden phrase"
}
```

Input available to every rule:

| Field | Type | Description |
|---|---|---|
| `input.path` | `string` | Path to the scanned file |
| `input.content` | `string` | Full file content |
| `input.lines` | `array<string>` | Content split by newline |

**Using a local directory**

```bash
oy scan .claude/ --policies ./my-policies
```

**Using a Git-hosted repository**

```bash
oy repo add github.com/myorg/my-oy-policies
oy scan .claude/
```

## CI integration

`oy` exits with code `1` when violations are found, making it a drop-in gate in any pipeline. Pin to a specific version tag in production for reproducible results.

**GitHub Actions — action (recommended)**

```yaml
- uses: aljoshare/oy-action@v1
  with:
    path: .claude/

- uses: aljoshare/oy-action@v1
  with:
    path: CLAUDE.md
```

The official policy collection is cloned automatically. See [aljoshare/oy-action](https://github.com/aljoshare/oy-action) for the full input reference.

**GitLab CI**

```yaml
scan-agent-files:
  image: ghcr.io/aljoshare/oy:v0.1.0
  variables:
    GIT_STRATEGY: clone
  before_script:
    - git clone https://github.com/aljoshare/oy-policies.git
  script:
    - oy scan .claude/ --policies ./oy-policies
    - oy scan CLAUDE.md AGENT.md --policies ./oy-policies
```

**GitHub Actions — binary**

```yaml
- name: Scan agent files for malicious instructions
  run: |
    go install github.com/aljoshare/oy@v0.1.0
    oy repo add github.com/aljoshare/oy-policies
    oy scan .claude/
    oy scan CLAUDE.md AGENT.md
```

## Troubleshooting

**`no policy repositories configured`**
No repos registered yet. Run `oy repo add github.com/aljoshare/oy-policies`.

**`cloning "...": ...`**
`git` is not installed or the URL is unreachable. Verify `git` is in your `PATH`.

**`no .rego files found`**
The directory passed to `--policies` contains no `.rego` files, or a registered repository cache is empty. Run `oy repo list` to check local paths.

**`scanning "...": ...`**
The path passed to `oy scan` does not exist or is not readable.

## License

[MIT](LICENSE)
