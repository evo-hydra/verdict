# Seraph

Code quality gate for AI-generated code. Mutation testing, static analysis, flaky test detection, and risk scoring in one pipeline.

Seraph takes a git diff and stress-tests it across 5 dimensions before it ships.

## Install

```bash
pip install seraph-ai
```

With optional tools:

```bash
pip install "seraph-ai[mutation]"   # mutmut for mutation testing
pip install "seraph-ai[sentinel]"   # git-sentinel for risk signals
pip install "seraph-ai[all]"        # everything
```

## Quick Start

```bash
# Assess current changes (skipping heavy steps for speed)
seraph assess --skip-baseline --skip-mutations

# Full assessment with mutation testing
seraph assess

# View past assessments
seraph history

# JSON output for CI integration
seraph assess --json

# Debug mode
seraph assess --verbose
```

## What It Does

Seraph runs your code changes through 5 tests and produces an overall grade (A-F):

| Dimension | Weight | What It Checks |
|-----------|--------|----------------|
| **Mutation Score** | 30% | Deliberately breaks your code — do your tests catch it? |
| **Static Cleanliness** | 20% | Ruff + mypy findings weighted by severity |
| **Test Baseline** | 15% | Runs tests 3x to detect flaky tests |
| **Sentinel Risk** | 20% | Hot files, pitfall patterns, and risk signals from git history |
| **Co-change Coverage** | 15% | Did you forget files that historically change together? |

Grades: **A** >= 90, **B** >= 75, **C** >= 60, **D** >= 40, **F** < 40

## MCP Server

Seraph works as an MCP server for AI assistants (Claude, etc.):

```bash
seraph-mcp
```

Tools: `seraph_assess`, `seraph_mutate`, `seraph_history`, `seraph_feedback`

### Claude Desktop Config

```json
{
  "mcpServers": {
    "seraph": {
      "command": "seraph-mcp",
      "env": {
        "SERAPH_REPO_PATH": "/path/to/your/repo"
      }
    }
  }
}
```

## Configuration

Create `.seraph/config.toml` in your repo to customize:

```toml
[timeouts]
mutation_per_file = 300
static_analysis = 60

[scoring]
mutation_weight = 0.40
static_weight = 0.15

[pipeline]
baseline_runs = 5

[retention]
retention_days = 30

[logging]
level = "DEBUG"
```

Environment variables override TOML (e.g. `SERAPH_TIMEOUT_MUTATION_PER_FILE=300`).

## Commands

```bash
seraph assess [repo_path]    # Run full assessment
seraph history [repo_path]   # View past assessments
seraph feedback <id> <outcome>  # Submit feedback (accepted/rejected/modified)
seraph prune [repo_path]     # Delete old data (--days N --yes)
```

## Works With

- **[Sentinel](https://github.com/evo-hydra/sentinel)** — Git history intelligence (hot files, co-change patterns, pitfall detection)
- **mutmut** — Mutation testing
- **ruff** — Fast Python linter
- **mypy** — Type checker

## Part of the EvoIntel MCP Suite

Seraph solves **AI Blindness #4: Code Quality** — mutation survival, flaky tests, and risk signals that "all tests pass" will never reveal.

Part of the [EvoIntel MCP Suite](https://evolvingintelligence.ai) by Evolving Intelligence AI: five tools for five blindnesses no model improvement will ever fix.

| Tool | Blindness | Install |
|------|-----------|---------|
| [Sentinel](https://github.com/evo-hydra/sentinel) | Project History | `pip install git-sentinel` |
| [Niobe](https://github.com/evo-hydra/niobe) | Runtime Behavior | `pip install niobe` |
| [Merovingian](https://github.com/evo-hydra/merovingian) | Cross-Service Dependencies | `pip install merovingian` |
| **Seraph** | Code Quality | `pip install seraph-ai` |
| [Anno](https://github.com/evo-hydra/anno) | Web Content | `npm install -g @evointel/anno` |

## License

MIT
