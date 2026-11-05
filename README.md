# Arc (Agent Runtime Customization)

[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![Version](https://img.shields.io/badge/version-1.0.0-blue)

**Arc** is a configuration compiler and runtime guard engine for AI coding assistants. Developers describe instructions, roles, skills and guards once in an `arc.yaml` manifest; Arc compiles it into the native files of the supported providers, Google Antigravity/Gemini and Codex, and evaluates the guards while the agent runs. Prebuilt release binaries and source builds are available for Windows, Linux, and macOS.

**Contents**

- [Arc (Agent Runtime Customization)](#arc-agent-runtime-customization)
  - [How it works](#how-it-works)
  - [Install](#install)
  - [Usage](#usage)
    - [Quick start](#quick-start)
    - [Commands](#commands)
    - [Supported providers](#supported-providers)
  - [Documentation](#documentation)
    - [Roadmap](#roadmap)
  - [Development](#development)
    - [Versioning](#versioning)
  - [License](#license)

## How it works

Arc has two parts:

1. **Compiler (`arc build`)**: reads and validates the manifest and emits provider-native artifacts for the selected providers and operating systems: `AGENTS.md`, hook configuration and scripts, and the intermediate representation `arc_ir.json`.
2. **Runtime (`arc hook run`)**: the generated hooks call it on each provider event. It evaluates the declared guards and returns a verdict (continue, deny, ask or message), which the provider adapter translates into the provider's own payload.

Arc does not replace the agent loop. The provider keeps running the agent, the model and the tools; Arc is the external policy layer around them.

Guards come in two kinds. Lifecycle guards run when a session starts or ends. Tool guards match a tool call with a regular expression. Each guard requires evidence, either a deterministic `probe` (a local command) or a semantic `decide` (a model-backed check), and says what to do on failure: `deny`, `ask` or `message`. Providers do not support every combination: `arc capabilities` prints the matrix, and `arc build` reports how each guard is enforced or rejects it.

## Install

Arc provides prebuilt binary releases as well as source builds.

**Prebuilt binary releases:** Install Arc directly with a single command via the GitHub release URLs, or run the [install.ps1](install.ps1) / [install.sh](install.sh) scripts locally. The installer scripts verify the downloaded archive against `SHA256SUMS`, install `arc` and the `arc-decision-ui-host` sidecar co-located into `$HOME/.arc/bin` (or a custom directory via `-InstallDir` / `--install-dir`), and configure `PATH` unless `-NoModifyPath` / `--no-modify-path` is specified.

On Windows (PowerShell):

```powershell
# One-liner from GitHub release:
irm https://github.com/Jose-Polanco-Oxte/Agent-Runtime-Customization/releases/latest/download/install.ps1 | iex

# Or run locally if downloaded:
powershell -ExecutionPolicy Bypass -File install.ps1
```

On Linux and macOS:

```bash
# One-liner from GitHub release:
curl -fsSL https://github.com/Jose-Polanco-Oxte/Agent-Runtime-Customization/releases/latest/download/install.sh | sh

# Or run locally if downloaded:
./install.sh
```

**Building from source:** Clone the repository and run one of the build scripts from its root. Prerequisites: stable Rust with Cargo (edition 2024), Node.js 24 and npm for the decision UI frontend, and Python 3.13 for the end-to-end tests. The decision UI uses Tauri, which needs WebView2 and the MSVC build tools on Windows, WebKitGTK development packages on Linux, or the Xcode command-line tools on macOS.

On Windows:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 -Install
```

On Linux and macOS:

```bash
./build.sh --install
```

The scripts build the frontend and both executables, install `arc` with `cargo install`, and copy the sidecar `arc-decision-ui-host` next to it. Without a custom directory, both land in `$CARGO_HOME/bin` (`~/.cargo/bin` by default). Add `-Check` (`--check` for `build.sh`) to run a smoke test after the build. Use `-InstallDir` (`--install-dir` for `build.sh`) to select another directory.

Verify the installation:

```bash
arc --version
```

It prints `arc 1.0.0` for this release. Three things to know:

- The sidecar `arc-decision-ui-host` must stay in the same directory as `arc`.
- Generated hooks call `arc` by name, so `arc` must be on `PATH`. To embed another executable path instead, set `ARC_BIN` when you run `arc build`.
- To rebuild faster when `ui/decision/dist` is already up to date, add `-SkipFrontend` (`--skip-frontend` for the shell script).

## Usage

### Quick start

This builds a minimal project in an empty directory. It runs `git init -q` first so the guard's `git rev-parse` probe has a repository work tree, creates the instructions file and a manifest with one tool guard that blocks force pushes, and compiles for every provider.

```bash
git init -q
mkdir -p arc
echo "Follow the project conventions." > arc/instructions.md
cat > arc.yaml <<'YAML'
schema: '1.0'

root:
  workdir: 'arc'
  instructions: 'instructions.md'

guards:
  tools:
    block_force_push:
      matches:
        regex:
          - 'git\s+push\s+.*--force'
      require:
        probe:
          use: 'git rev-parse --is-inside-work-tree'
          in:
            - allow
      on_failure:
        action: deny
        feedback: |
          Force pushes are not allowed.
YAML
arc build
```

`arc build` exits 0 and writes, next to `arc.yaml`:

- `AGENTS.md` and the `.agents/` directory (`.agents/AGENTS.md`, `.agents/arc_ir.json`, `.agents/hooks.json`);
- the `.codex/` directory (`.codex/arc_ir.json`, `.codex/hooks.json`);
- the `.arc/` directory with `.arc/build.lock`, `.arc/build_manifest.json` and `.arc/arc-capabilities.json`.

The build prints a capability report per provider and a Codex activation note. For Codex, restart Codex CLI, trust the project `.codex` layer and review the generated hooks with the /hooks command. Codex Desktop builds that do not expose the /hooks trust flow do not support project-hook enforcement; use Codex CLI for guarded sessions.

Every build registers the exact intermediate representation file it wrote in Arc's local runtime database. If `.agents/arc_ir.json` is edited afterwards, hooks fail closed; run `arc build` again after intentional changes.

Next steps: the [usage guide](docs/USAGE.md) covers the configuration and the commands, and [examples/README.md](examples/README.md) describes six complete sample projects.

### Commands

| Command            | What it does                                                                                                                      |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `arc build`        | Compiles the manifest into provider artifacts.                                                                                    |
| `arc capabilities` | Prints the capability matrix of each provider and checks the project against it.                                                  |
| `arc hook run`     | Evaluates one provider hook event read from stdin and prints the verdict. The generated hooks call it; you rarely run it by hand. |
| `arc monitor`      | Reads the structured runtime event journal.                                                                                       |
| `arc mcp serve`    | Experimental stdio MCP server with an `arc_request_decision` tool.                                                                |
| `arc decision ask` | Shows an Allow / Deny dialog and prints the decision as JSON.                                                                     |

Run `arc <command> --help` for every flag; the usage guide documents them too.

`--target` takes `gemini`, `codex` or `all` (the default), and `--os` takes `windows`, `linux`, `macos`, `host` or `all` (the default). `--path` is an exact manifest file, not a directory; without it, Arc looks for `arc.yaml` from the current directory upward. A relative `workdir` is resolved from the directory of the manifest.

```bash
# Build for Codex only, for the current OS, into ./out
arc build --path examples/06-incident-response/arc.yaml --target codex --os host -o out

# Build for several targets and operating systems
arc build --target gemini,codex --os windows,linux

# Show the capability matrix for Codex
arc capabilities --target codex --path examples/06-incident-response/arc.yaml
```

### Supported providers

Arc compiles for two providers: Gemini (Google Antigravity) and Codex. `arc capabilities` shows them side by side as `Gemini (AGY)` — where `AGY` stands for Antigravity — and `Codex`, with four support tiers: `Supported`, `Emulated`, `Partial` and `Unsupported`. Codex CLI coverage is partial for several controls, and the build report says where.

## Documentation

- [Usage guide](docs/USAGE.md): configuration, commands and provider behavior.
- [Architecture](docs/ARCHITECTURE.md): internal compiler, capability resolution, decision evaluation and runtime model.
- [Examples](examples/README.md): six sample projects with a manual acceptance workflow.
- [Decision UI sidecar](docs/ARCHITECTURE.md#decision-ui-sidecar): how the decision dialog and its sidecar are built and resolved.

### Roadmap

Integrations beyond the current Gemini/Antigravity and Codex adapters are aspirational and are not compiled targets today. The phased plan is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Development

Run these from the repository root. The first block is the test suite; the second holds the lint and build checks (the project's own lint run adds extra warning flags).

```bash
cargo test --workspace --locked
npm --prefix ui/decision run test
python -m unittest discover -s tests/provider_e2e -p "test_*.py"
python tests/e2e/runner.py
```

```bash
cargo clippy --workspace --lib --bins --locked --offline
npm --prefix ui/decision run check:audit
cargo check --workspace --all-targets --locked --offline
npm --prefix ui/decision run build
```

To work on the decision dialog without rebuilding Rust, run `npm --prefix ui/decision run dev` and open `http://127.0.0.1:5173/?fixture=default`; the fixtures `minimal`, `long`, `unicode` and `light` exercise other layouts. See the [decision UI sidecar](docs/ARCHITECTURE.md#decision-ui-sidecar) architecture section for the security boundaries.

### Versioning

Arc follows Semantic Versioning, with release 1.0.0. The `version` field in `Cargo.toml` is the single source of truth. `arc --version` reports the executable that your shell resolves; on Windows, compare it with `Get-Command arc`. Stable releases maintain compatibility for configuration manifests and generated runtime hooks.

## License

Arc is dual-licensed under the MIT License or the Apache License 2.0 (MIT OR Apache-2.0), at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for the full license terms.
