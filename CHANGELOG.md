# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-05

### Added
- **Unified Policy Compiler (`arc build`)**: Compiles single-source `arc.yaml` declarations into provider-native artifacts for Google Antigravity/Gemini (`AGENTS.md`, `hooks.json`, hook scripts) and Codex, as well as a signed canonical intermediate representation (`arc_ir.json`).
- **Runtime Guard Engine (`arc hook run`)**: Enforces lifecycle guards (`start`, `stop`) and tool call pattern guards (`pre_tool_use`) using deterministic command probes (`probe`) and semantic validation checks (`decide`), returning structured verdicts (`continue`, `deny`, `ask`, `message`).
- **Cross-Platform Decision UI (`arc-decision-ui-host`)**: Embedded Tauri sidecar providing interactive human-in-the-loop decision dialogs on Windows (WebView2), Linux (WebKitGTK), and macOS, featuring isolated per-session user data directories and automatic system theme detection (Dark/Light).
- **Capability Matrix Engine (`arc capabilities`)**: Inspects provider features and reports compatibility tiers (`Supported`, `Emulated`, `Partial`, `Unsupported`) against project manifests.
- **Runtime Observability (`arc monitor`)**: Append-only SQLite state store journaling every evaluation, tool call, authorization, and probe execution.
- **Model Context Protocol Support (`arc mcp serve`)**: Stdio MCP server exposing decision dialogs via the `arc_request_decision` tool.
- **Cross-Platform Automated Installers**:
  - `install.ps1` for Windows with SHA256 checksum verification and user/machine `PATH` persistence.
  - `install.sh` for Linux and macOS supporting standard shell pipelines (`curl | sh`).
- **Automated Multi-Platform Release Pipeline**: GitHub Actions release workflow packaging signed zip and tar.gz archives for:
  - `x86_64-pc-windows-msvc`
  - `x86_64-unknown-linux-gnu`
  - `x86_64-apple-darwin`
  - `aarch64-apple-darwin`
- **Comprehensive Test Harness**: Cross-platform E2E test suites for provider contracts (Codex, Gemini) and end-to-end WebDriver UI integration testing.
- **Dual Licensing**: Published under MIT OR Apache-2.0 terms.
