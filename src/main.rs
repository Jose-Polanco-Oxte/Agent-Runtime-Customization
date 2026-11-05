use anyhow::{Context, Result, bail};
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum, value_parser};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use arc::compiler::validator::SemanticValidator;
use arc::{
    AgyAdapter, AgyPreInvocationInput, AgyPreToolUseInput, AgyStopInput, ArcRuntimeSession,
    CodexAdapter, CodexPreToolUseInput, CodexSessionStartInput, CodexStopInput, CollisionDetector,
    CoordinationInput, EmissionContext, EmitterRegistry, EvaluationSnapshot, EventQuery,
    ExactAuthorizationContext, GuardActivation, GuardExecutionCoordinator, GuardExecutionKey,
    GuardExecutionStateStore, InteractiveResolutionContext, NewObservabilityEvent,
    ObservabilityJournal, OsTarget, ProviderSignals, ProviderTarget, ReentryKind, RuntimeDirective,
    RuntimeDisposition, SqliteStateStore, ViolationHandling, canonical_workspace_root,
    check_project_compatibility, default_state_database_path, discover_arc_root,
    generate_capabilities_table, load_project, lower, new_invocation_id, recover_pending_build,
    resolve_explicit_manifest_file, write_artifacts_with_trust,
};

#[derive(Debug, Parser)]
#[command(name = "arc", version, disable_version_flag = true)]
#[command(about = "Arc - Agent Runtime Customization compiler and guard engine", long_about = None)]
struct Cli {
    /// Print version information
    #[arg(
        short = 'v',
        long = "version",
        visible_short_alias = 'V',
        action = ArgAction::Version
    )]
    short_version: Option<bool>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ProviderSelectionArg {
    All,
    Gemini,
    Codex,
}

impl ProviderSelectionArg {
    fn provider(self) -> Option<ProviderTarget> {
        match self {
            Self::All => None,
            Self::Gemini => Some(ProviderTarget::Gemini),
            Self::Codex => Some(ProviderTarget::Codex),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HookProviderArg {
    Gemini,
    Codex,
}

impl HookProviderArg {
    fn target(self) -> ProviderTarget {
        match self {
            Self::Gemini => ProviderTarget::Gemini,
            Self::Codex => ProviderTarget::Codex,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OperatingSystemArg {
    All,
    Host,
    Windows,
    Linux,
    Macos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HookEventArg {
    #[value(alias = "pretooluse")]
    PreToolUse,
    #[value(alias = "sessionstart")]
    SessionStart,
    Stop,
    #[value(alias = "preinvocation")]
    PreInvocation,
}

impl HookEventArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreToolUse => "pre-tool-use",
            Self::SessionStart => "session-start",
            Self::Stop => "stop",
            Self::PreInvocation => "pre-invocation",
        }
    }

    fn supports_provider(self, provider: ProviderTarget) -> bool {
        matches!(
            (provider, self),
            (
                ProviderTarget::Codex,
                Self::PreToolUse | Self::SessionStart | Self::Stop
            ) | (
                ProviderTarget::Gemini,
                Self::PreToolUse | Self::PreInvocation | Self::Stop
            )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DecisionUiArg {
    Auto,
    Native,
    Provider,
}

fn capability_decision_ui(value: DecisionUiArg) -> arc::DecisionUiMode {
    match value {
        DecisionUiArg::Auto => arc::DecisionUiMode::Auto,
        DecisionUiArg::Native => arc::DecisionUiMode::Native,
        DecisionUiArg::Provider => arc::DecisionUiMode::Provider,
    }
}

fn cli_decision_environment(provider: ProviderTarget) -> arc::DecisionEnvironment {
    match provider {
        ProviderTarget::Gemini => arc::DecisionEnvironment {
            provider_native: true,
            arc_embedded_ui: true,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        },
        ProviderTarget::Codex => arc::DecisionEnvironment::codex_hook_with_embedded_ui(),
        ProviderTarget::Claude | ProviderTarget::OpenCode => arc::DecisionEnvironment {
            provider_native: false,
            arc_embedded_ui: false,
            arc_owns_app_server_session: false,
            direct_mcp_channel: false,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MonitorLevelArg {
    Debug,
    Info,
    Warn,
    Error,
}

impl MonitorLevelArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MonitorFormatArg {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Builds provider artifacts and emits them to disk
    Build {
        /// Provider target: gemini, codex, or all
        #[arg(
            short,
            long,
            value_enum,
            ignore_case = true,
            value_delimiter = ',',
            default_values = ["all"]
        )]
        target: Vec<ProviderSelectionArg>,

        /// Operating system target: windows, linux, macos, host, or all
        #[arg(
            long,
            value_enum,
            ignore_case = true,
            value_delimiter = ',',
            default_values = ["all"]
        )]
        os: Vec<OperatingSystemArg>,

        /// Exact Arc manifest file path (default: discover from current directory and parents)
        #[arg(short, long)]
        path: Option<PathBuf>,

        /// Base output directory (default: workspace root)
        #[arg(short = 'o', long)]
        output_dir: Option<PathBuf>,
    },

    /// Displays provider capability matrices and validates project compatibility
    Capabilities {
        /// Provider target to inspect: gemini, codex, or all
        #[arg(short, long, value_enum, ignore_case = true)]
        target: Option<ProviderSelectionArg>,

        /// Exact Arc manifest file path (default: discover from current directory and parents)
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Hook commands invoked by provider adapters (e.g. AGY, Codex)
    Hook {
        #[command(subcommand)]
        subcommand: HookCommands,
    },

    /// Reads Arc's structured runtime event journal
    Monitor {
        /// Continue waiting for new events
        #[arg(long, conflicts_with = "clear")]
        follow: bool,
        /// Delete matching observability events and exit (runtime guard state is preserved)
        #[arg(long)]
        clear: bool,
        /// Resolve and filter by this workspace path
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Filter by a session identifier
        #[arg(long)]
        session: Option<String>,
        /// Attach to the latest known session (optionally within --workspace)
        #[arg(long, conflicts_with = "session")]
        latest: bool,
        /// Filter by an execution identifier
        #[arg(long)]
        execution: Option<String>,
        /// Minimum level: debug, info, warn, or error
        #[arg(long, value_enum, ignore_case = true, default_value = "debug")]
        level: MonitorLevelArg,
        /// Comma-separated event types
        #[arg(long, value_delimiter = ',')]
        events: Vec<String>,
        /// Output format: text or json
        #[arg(long, value_enum, ignore_case = true, default_value = "text")]
        format: MonitorFormatArg,
        /// Poll interval used with --follow
        #[arg(
            long,
            default_value_t = 250,
            requires = "follow",
            value_parser = value_parser!(u64).range(50..)
        )]
        poll_ms: u64,
    },

    /// Runs Arc protocol integrations
    Mcp {
        #[command(subcommand)]
        subcommand: McpCommands,
    },

    /// Requests a structured decision through an Arc-owned portable UI
    Decision {
        #[command(subcommand)]
        subcommand: DecisionCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DecisionCommands {
    /// Shows an Allow / Deny dialog and prints the decision as JSON
    Ask {
        #[arg(long, default_value = "Arc policy decision")]
        title: String,
        #[arg(long)]
        message: String,
        /// Use an interactive terminal instead of a graphical dialog
        #[arg(long)]
        terminal: bool,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommands {
    /// Runs the experimental Arc decision-dialog MCP server over stdio
    Serve,
}

#[derive(Debug, Subcommand)]
enum HookCommands {
    /// Evaluates an in-flight hook event from stdin and returns verdict JSON on stdout
    Run {
        /// Provider hook event to evaluate
        #[arg(short, long, value_enum, ignore_case = true)]
        event_type: HookEventArg,

        /// Path to compiled arc_ir.json (default: .agents/arc_ir.json)
        #[arg(short, long)]
        ir_path: Option<PathBuf>,

        /// Provider wire format; inferred from stdin when omitted
        #[arg(long, value_enum, ignore_case = true)]
        provider: Option<HookProviderArg>,

        /// User-decision transport strategy
        #[arg(long, value_enum, ignore_case = true, default_value = "auto")]
        decision_ui: DecisionUiArg,
    },
}

fn decision_response_json(response: &arc::DialogResponse) -> serde_json::Value {
    serde_json::json!({
        "schema": &response.schema,
        "request_id": &response.request_id,
        "bundle_fingerprint": &response.bundle_fingerprint,
        "decision": &response.decision,
        "transport": &response.transport,
        "theme": &response.theme,
        "message": &response.message,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(error) = validate_cli_relations(&cli) {
        error.exit();
    }

    match cli.command {
        Commands::Capabilities { target, path } => {
            let registry = EmitterRegistry::new();
            let available_providers = registry.providers();
            let providers =
                resolve_provider_selection(target.as_slice(), &available_providers, "--target")?;
            let (explicit_path, start_dir) = match path {
                Some(path) => (true, path),
                None => (
                    false,
                    std::env::current_dir()
                        .context("Failed to resolve the current directory for Arc discovery")?,
                ),
            };
            let manifest_path = if explicit_path {
                Some(resolve_explicit_manifest_file(&start_dir).with_context(|| {
                    format!(
                        "Failed to resolve the explicit Arc manifest {:?}",
                        start_dir
                    )
                })?)
            } else {
                discover_arc_root(&start_dir).ok()
            };

            println!("{}", generate_capabilities_table(&providers));

            match manifest_path {
                Some(arc_yaml_path) => {
                    println!("Inspecting project at: {:?}", arc_yaml_path);
                    let project = load_project(&arc_yaml_path)?;

                    println!("\nProject Compatibility Report:");
                    println!("--------------------------------------------------");
                    for provider in providers {
                        let diagnostics = check_project_compatibility(&project, provider);
                        if diagnostics.is_empty() {
                            println!("  [OK] 100% compatible with '{}'", provider);
                        } else {
                            println!(
                                "  [!] {} compatibility issues for '{}':",
                                diagnostics.len(),
                                provider
                            );
                            for diagnostic in diagnostics {
                                println!(
                                    "      * Guard '{}': {} ({})",
                                    diagnostic.guard_id, diagnostic.feature, diagnostic.reason
                                );
                            }
                        }
                    }
                    println!("--------------------------------------------------");
                }
                None => {
                    println!(
                        "(No arc.yaml found from {:?}; skipping project compatibility checks.)",
                        start_dir
                    );
                }
            }
        }

        Commands::Build {
            target,
            os,
            path,
            output_dir,
        } => {
            let (explicit_path, start_dir) = match path {
                Some(path) => (true, path),
                None => (
                    false,
                    std::env::current_dir()
                        .context("Failed to resolve the current directory for Arc discovery")?,
                ),
            };

            // Resolve and validate the complete CLI selection before reading project files.
            let registry = EmitterRegistry::new();
            let providers = resolve_provider_selection(&target, &registry.providers(), "--target")?;
            let target_os_list = resolve_os_selection(&os)?;
            let capability_target_oses = target_os_list
                .iter()
                .cloned()
                .map(OsTarget::new)
                .collect::<Result<Vec<_>>>()
                .context("Resolved build OS targets are invalid")?;

            // 1. Discover arc.yaml
            let arc_yaml_path = if explicit_path {
                resolve_explicit_manifest_file(&start_dir).with_context(|| {
                    format!(
                        "Failed to resolve the explicit Arc manifest {:?}",
                        start_dir
                    )
                })?
            } else {
                discover_arc_root(&start_dir)
                    .with_context(|| format!("Configuration discovery failed in {:?}", start_dir))?
            };
            println!("Found Arc configuration: {:?}", arc_yaml_path);

            // 2. Load project
            let project = load_project(&arc_yaml_path)
                .with_context(|| format!("Failed loading Arc project from {:?}", arc_yaml_path))?;
            println!("Loaded schema: {}", project.manifest.schema);
            println!("Declared skills: {}", project.skills.len());
            println!("Declared roles: {}", project.roles.len());
            println!(
                "Declared guards: {} lifecycle, {} tool",
                project.guards.lifecycle.len(),
                project.guards.tools.len()
            );

            // 3. Expand providers and OS target
            let os_display = if target_os_list.len() == 3 {
                "all (windows, linux, macos)".to_string()
            } else {
                target_os_list.join(", ")
            };

            println!(
                "Compilation matrix: {} provider(s), target OS: [{}]",
                providers.len(),
                os_display
            );

            // 4. Validate project compatibility for each requested target provider
            for provider in &providers {
                SemanticValidator::validate_project_for_provider(&project, *provider)
                    .with_context(|| {
                        format!("Capability validation failed for provider '{}'", provider)
                    })?;
            }

            let arc_root_dir = arc_yaml_path
                .parent()
                .unwrap_or_else(|| &start_dir)
                .to_path_buf();
            let base_out = output_dir.unwrap_or(arc_root_dir);
            let base_out = std::path::absolute(&base_out)
                .with_context(|| format!("Failed resolving output directory {:?}", base_out))?;
            warn_if_arc_state_not_ignored(&base_out);
            let trust_store = SqliteStateStore::open(&default_state_database_path()?)?;
            if base_out.exists() {
                recover_pending_build(&base_out, &trust_store).with_context(|| {
                    format!(
                        "Refusing to start a build with an unresolved transaction in {:?}",
                        base_out
                    )
                })?;
            }
            let mut all_artifacts = Vec::new();

            // 5. Lower and emit for all providers in memory
            for provider in &providers {
                println!("Compiling for target: {} on [{}]", provider, os_display);
                let ir = lower(&project, &target_os_list).with_context(|| {
                    format!(
                        "Failed lowering Arc project for target '{}' on [{}]",
                        provider, os_display
                    )
                })?;

                let primary_os = OsTarget::new(
                    target_os_list
                        .first()
                        .cloned()
                        .unwrap_or_else(|| std::env::consts::OS.to_string()),
                )
                .with_context(|| "Resolved target OS is invalid")?;

                let emission_ctx = EmissionContext {
                    provider: *provider,
                    target_os: primary_os,
                    environment: arc::ProviderEnvironment::Cli,
                    decision_ui: arc::DecisionUiMode::Auto,
                    decision_environment: cli_decision_environment(*provider),
                    base_output_path: base_out.clone(),
                    is_multi_target: providers.len() > 1,
                    arc_bin: None,
                };

                let emitter = registry.get(*provider).with_context(|| {
                    format!("No emitter registered for provider '{}'", provider)
                })?;

                let artifacts = emitter.emit(&ir, &emission_ctx).with_context(|| {
                    format!("Failed emitting artifacts for target '{}'", provider)
                })?;

                let reports = arc::target::capabilities::generate_degradation_report_for_targets(
                    &project,
                    *provider,
                    emission_ctx.environment,
                    &capability_target_oses,
                    emission_ctx.decision_ui,
                    emission_ctx.decision_environment.clone(),
                );
                println!(
                    "{}",
                    arc::target::capabilities::format_degradation_table(&reports, *provider)
                );

                all_artifacts.extend(artifacts);
            }

            // Emit arc-capabilities.json artifact for multi-dimensional capability inspection (H9)
            let capabilities_json = serde_json::json!({
                "schema_version": "1.0",
                "providers": providers.iter().map(|p| {
                    let caps = arc::ProviderCapabilities::for_provider(*p);
                    let reports = arc::target::capabilities::generate_degradation_report_for_targets(
                        &project,
                        *p,
                        arc::ProviderEnvironment::Cli,
                        &capability_target_oses,
                        arc::DecisionUiMode::Auto,
                        cli_decision_environment(*p),
                    );
                    serde_json::json!({
                        "provider": p,
                        "capabilities": caps,
                        "guards": reports,
                    })
                }).collect::<Vec<_>>(),
            });
            let rel_cap_path = PathBuf::from(".arc/arc-capabilities.json");
            all_artifacts.push(arc::emitters::GeneratedArtifact {
                provider: providers[0],
                target_os: OsTarget::host()?,
                relative_path: rel_cap_path,
                content: serde_json::to_string_pretty(&capabilities_json).unwrap_or_default(),
                is_executable: false,
            });

            // 6. Validate no cross-provider file collisions in memory before any writes (M8)
            CollisionDetector::verify_no_collisions(&all_artifacts)
                .context("File collision detected across provider targets")?;

            // 7. Register IR snapshots through the writer's finalizer. The
            // finalizer runs while artifact backups still exist, so a trust
            // failure rolls the output transaction back too (M8, H8).
            let generated_ir_entries: Vec<(PathBuf, Vec<u8>)> = all_artifacts
                .iter()
                .filter(|artifact| {
                    artifact.relative_path == std::path::Path::new(".codex/arc_ir.json")
                        || artifact.relative_path == std::path::Path::new(".agents/arc_ir.json")
                })
                .map(|artifact| {
                    (
                        artifact.relative_path.clone(),
                        artifact.content.as_bytes().to_vec(),
                    )
                })
                .collect();
            write_artifacts_with_trust(
                &base_out,
                &all_artifacts,
                &trust_store,
                &generated_ir_entries,
            )
            .with_context(|| format!("Failed writing generated artifacts to {:?}", base_out))?;

            for provider in &providers {
                if *provider == ProviderTarget::Codex
                    && all_artifacts.iter().any(|artifact| {
                        artifact.relative_path == PathBuf::from(".codex/hooks.json")
                    })
                {
                    println!(
                        "  -> Codex CLI activation required: restart Codex CLI, trust the project .codex layer, and review the generated hooks with /hooks."
                    );
                    println!(
                        "  -> WARNING: project-hook enforcement is not supported in Codex Desktop builds that do not expose the /hooks trust flow; use Codex CLI for guarded sessions."
                    );
                }
                if project.guards.lifecycle.values().any(|guard| {
                    guard
                        .trigger
                        .to_vec()
                        .contains(&arc::manifest::schema::LifecycleTrigger::End)
                }) {
                    let capabilities = arc::ProviderCapabilities::for_provider(*provider);
                    if capabilities.lifecycle_structured_decision
                        == arc::CapabilityLevel::Unsupported
                    {
                        println!(
                            "  -> WARNING: {} can continue a failed Stop guard but has no verified structured lifecycle decision receipt. Arc bounds stalled remediation with a terminal abort; it cannot offer Allow/Deny deterministically on this target.",
                            provider
                        );
                    }
                }
            }

            println!("Build completed successfully in {:?}!", base_out);
        }

        Commands::Hook { subcommand } => match subcommand {
            HookCommands::Run {
                event_type,
                ir_path,
                provider,
                decision_ui,
            } => {
                let mut resolved_target = provider
                    .map(HookProviderArg::target)
                    .or_else(|| infer_provider_from_ir_path(ir_path.as_deref()))
                    .unwrap_or_else(|| match event_type {
                        HookEventArg::SessionStart => ProviderTarget::Codex,
                        HookEventArg::PreInvocation
                        | HookEventArg::PreToolUse
                        | HookEventArg::Stop => ProviderTarget::Gemini,
                    });
                if let Err(_err) = run_hook(
                    event_type,
                    ir_path,
                    provider,
                    decision_ui,
                    &mut resolved_target,
                ) {
                    eprintln!(
                        "[ARC HOOK ERROR] {}: {:#}",
                        PUBLIC_HOOK_FAILURE_REASON, _err
                    );
                    emit_hook_failure(
                        event_type,
                        resolved_target == ProviderTarget::Codex,
                        PUBLIC_HOOK_FAILURE_REASON,
                    );
                }
            }
        },
        Commands::Monitor {
            follow,
            clear,
            workspace,
            session,
            latest,
            execution,
            level,
            events,
            format,
            poll_ms,
        } => {
            run_monitor(
                follow, clear, workspace, session, latest, execution, level, events, format,
                poll_ms,
            )?;
        }
        Commands::Mcp { subcommand } => match subcommand {
            McpCommands::Serve => {
                let stdin = io::stdin();
                let stdout = io::stdout();
                arc::mcp::serve(stdin.lock(), stdout.lock())?;
            }
        },
        Commands::Decision { subcommand } => match subcommand {
            DecisionCommands::Ask {
                title,
                message,
                terminal,
            } => {
                let response = if terminal {
                    let req_id = arc::new_invocation_id();
                    let decision = arc::decision_ui::request_terminal_decision(&title, &message)?;
                    arc::DialogResponse {
                        schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
                        request_id: req_id.clone(),
                        bundle_fingerprint: req_id,
                        decision,
                        transport: "terminal".into(),
                        theme: "terminal".into(),
                        message: None,
                    }
                } else {
                    let req_id = arc::new_invocation_id();
                    let request = arc::DialogRequest::guard_failures(
                        req_id.clone(),
                        title,
                        "once",
                        vec![arc::DialogViolationItem {
                            guard_id: "cli_ask".into(),
                            summary: message,
                            configured_feedback: None,
                            auditor_findings: None,
                            scope: "once".into(),
                            failed_probes: Vec::new(),
                        }],
                        req_id,
                        0,
                    );
                    arc::decision_ui::request_embedded_decision(
                        &request,
                        Duration::from_secs(
                            arc::manifest::schema::DEFAULT_DECISION_TIMEOUT_SECONDS,
                        ),
                    )?
                };
                println!(
                    "{}",
                    serde_json::to_string(&decision_response_json(&response))?
                );
            }
        },
    }

    Ok(())
}

fn warn_if_arc_state_not_ignored(output_root: &Path) {
    let Some(existing_parent) = output_root.ancestors().find(|path| path.exists()) else {
        return;
    };
    let candidate = output_root.join(".arc");
    let result = Command::new("git")
        .arg("-C")
        .arg(existing_parent)
        .args(["check-ignore", "--quiet", "--"])
        .arg(&candidate)
        .output();
    if matches!(result, Ok(output) if output.status.code() == Some(1)) {
        eprintln!(
            "Warning: Arc state at {:?} is not ignored by Git. Add '.arc/' to the output repository's ignore rules.",
            candidate
        );
    }
}

fn validate_cli_relations(cli: &Cli) -> std::result::Result<(), clap::Error> {
    match &cli.command {
        Commands::Build { target, os, .. } => {
            if target.contains(&ProviderSelectionArg::All) && target.len() > 1 {
                return Err(Cli::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "'--target all' cannot be combined with specific provider targets",
                ));
            }
            if os.contains(&OperatingSystemArg::All) && os.len() > 1 {
                return Err(Cli::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "'--os all' cannot be combined with specific OS targets",
                ));
            }
        }
        Commands::Hook {
            subcommand:
                HookCommands::Run {
                    event_type,
                    provider: Some(provider),
                    ..
                },
        } => {
            let target = provider.target();
            if !event_type.supports_provider(target) {
                return Err(Cli::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    format!(
                        "'--event-type {}' is not supported with '--provider {}'",
                        event_type.as_str(),
                        target.as_str()
                    ),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

fn run_monitor(
    follow: bool,
    clear: bool,
    workspace: Option<PathBuf>,
    mut session: Option<String>,
    latest: bool,
    execution: Option<String>,
    level: MonitorLevelArg,
    events: Vec<String>,
    format: MonitorFormatArg,
    poll_ms: u64,
) -> Result<()> {
    let state_path = default_state_database_path()?;
    SqliteStateStore::open(&state_path)
        .context("failed initializing Arc runtime state for monitor")?;
    let journal = ObservabilityJournal::open(&state_path)?;
    let workspace_id = if let Some(path) = workspace {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed canonicalizing monitor workspace {path:?}"))?;
        journal
            .workspace_id(&canonical)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "workspace is not registered in Arc runtime state yet: {canonical:?}"
                )
            })?
            .into()
    } else {
        None
    };
    if latest {
        session = journal.latest_session(workspace_id.as_deref())?;
        if session.is_none() {
            bail!("no observed Arc session matches the requested scope");
        }
    }
    if clear {
        let deleted = journal.clear_events(
            workspace_id.as_deref(),
            session.as_deref(),
            execution.as_deref(),
        )?;
        println!("Cleared {deleted} observability event(s). Runtime guard state was preserved.");
        return Ok(());
    }
    if format == MonitorFormatArg::Text {
        println!("ARC RUNTIME MONITOR");
        if let Some(value) = &workspace_id {
            println!("Workspace: {value}");
        }
        if let Some(value) = &session {
            println!("Session:   {value}");
        }
        if let Some(value) = &execution {
            println!("Execution: {value}");
        }
        println!();
    }
    // Live monitoring follows from "now". Historical replay remains the non-follow behavior.
    let mut after_id = if follow {
        journal.latest_event_id()?
    } else {
        0
    };
    loop {
        let batch = journal.query(&EventQuery {
            after_id,
            workspace_id: workspace_id.clone(),
            session_id: session.clone(),
            execution_id: execution.clone(),
            minimum_level: Some(level.as_str().to_string()),
            event_types: events.clone(),
            limit: 500,
        })?;
        for event in &batch {
            after_id = after_id.max(event.id);
            if format == MonitorFormatArg::Json {
                println!("{}", serde_json::to_string(event)?);
            } else {
                let seconds = event.timestamp_unix_ms / 1000;
                let millis = event.timestamp_unix_ms.rem_euclid(1000);
                println!(
                    "{seconds}.{millis:03}  {}",
                    event.event_type.to_ascii_uppercase()
                );
                if let Some(value) = &event.guard_id {
                    println!("               guard={value}");
                }
                if let Some(value) = &event.execution_id {
                    println!("               execution={value}");
                }
                if let Some(value) = &event.reason_code {
                    println!("               reason={value}");
                }
                if let Some(value) = event.duration_ms {
                    println!("               duration={value}ms");
                }
                if event.details != serde_json::Value::Null
                    && event.details != serde_json::json!({})
                {
                    println!("               details={}", event.details);
                }
                println!();
            }
        }
        if !follow {
            break;
        }
        thread::sleep(Duration::from_millis(poll_ms));
    }
    Ok(())
}

fn generated_output_root_for_ir(ir_path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(ir_path)
        .with_context(|| format!("Failed resolving generated IR path {ir_path:?}"))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Generated IR path has no parent: {absolute:?}"))?;
    match parent.file_name().and_then(|name| name.to_str()) {
        Some(".codex" | ".agents") => parent
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("Generated IR provider directory has no parent")),
        _ => Ok(parent.to_path_buf()),
    }
}

fn run_hook(
    event_type: HookEventArg,
    ir_path: Option<PathBuf>,
    provider_hint: Option<HookProviderArg>,
    decision_ui: DecisionUiArg,
    resolved_target: &mut ProviderTarget,
) -> Result<()> {
    let started = std::time::Instant::now();
    let mut stdin_raw = String::new();
    let _ = io::stdin().read_to_string(&mut stdin_raw);
    let stdin_input = stdin_raw.trim_start_matches('\u{feff}').trim().to_string();

    let target = resolve_hook_target(event_type, ir_path.as_deref(), provider_hint, &stdin_input);
    *resolved_target = target;
    let is_codex = target == ProviderTarget::Codex;

    // Prevent recursive hook executions when Arc calls an agent CLI for decisions (H3)
    if !is_codex {
        if let Ok(marker) = std::env::var(arc::ARC_RECURSION_MARKER_ENV) {
            if marker == arc::ARC_RECURSION_INTERNAL_TOKEN
                && should_bypass_recursive_agy_hook(event_type, &stdin_input)
            {
                if let Ok(state_path) = default_state_database_path() {
                    if let Ok(journal) = ObservabilityJournal::open(&state_path) {
                        let _ = journal.append(NewObservabilityEvent {
                            event_type: "RecursionBypass".into(),
                            level: "info".into(),
                            provider: Some(target.as_str().to_string()),
                            reason_code: Some("internal_recursion_marker_match".into()),
                            details: serde_json::json!({
                                "marker": arc::ARC_RECURSION_INTERNAL_TOKEN,
                                "event": event_type.as_str(),
                                "provider": target.as_str(),
                            }),
                            ..Default::default()
                        });
                    }
                }
                emit_fail_safe_allow_for_event(event_type, is_codex);
                return Ok(());
            }
        }
    }

    let resolved_ir_path = match resolve_ir_file(ir_path, &stdin_input, is_codex) {
        Some(path) => path,
        None => {
            validate_hook_provider_event(target, event_type)?;
            return Err(anyhow::anyhow!(
                "No BehaviorIR found from the hook cwd or its parent directories"
            )
            .context(HookFailureContext::IrResolution));
        }
    };
    let state_path = default_state_database_path()?;
    let state_store = std::sync::Arc::new(SqliteStateStore::open(&state_path)?);
    let recovery_root = generated_output_root_for_ir(&resolved_ir_path)
        .context(HookFailureContext::IrResolution)?;
    recover_pending_build(&recovery_root, &state_store)
        .context("Arc refused an unresolved or ambiguous build transaction")
        .context(HookFailureContext::IrResolution)?;
    let snapshot = state_store
        .load_trusted_ir_snapshot(&resolved_ir_path)
        .with_context(|| "Arc refused an untrusted or modified BehaviorIR")
        .context(HookFailureContext::IrResolution)?;
    let resolved_ir_path = snapshot.canonical_ir_path().to_path_buf();
    let journal = ObservabilityJournal::open(&state_path).ok();
    let workspace_root = canonical_workspace_root(&resolved_ir_path)?;
    let workspace_id = state_store.resolve_workspace_id(&workspace_root)?;
    let session_id =
        extract_session_id_from_stdin(&stdin_input).unwrap_or_else(|| "hook-session".to_string());
    let turn_id = extract_optional_string(&stdin_input, &["turn_id", "turnId"]);
    let invocation_id = new_invocation_id();
    let provider_name = target.as_str().to_string();
    let observed = HookObservationContext {
        provider: provider_name,
        workspace_id: Some(workspace_id.clone()),
        session_id: session_id.clone(),
        turn_id,
        invocation_id: invocation_id.clone(),
    };
    append_observation(
        &journal,
        &observed,
        "HookReceived",
        "info",
        None,
        None,
        serde_json::json!({
            "event": event_type.as_str(),
            "payload_bytes": stdin_input.len(),
            "capture": "metadata"
        }),
    );
    let hook_result = (|| -> Result<()> {
        append_observation(
            &journal,
            &observed,
            "IrResolved",
            "info",
            None,
            Some(started.elapsed().as_millis() as i64),
            serde_json::json!({
                "source": resolved_ir_path.to_string_lossy(),
                "lifecycle_guards": snapshot.ir().lifecycle_guards.len(),
                "tool_guards": snapshot.ir().tool_guards.len()
            }),
        );
        validate_hook_provider_event(target, event_type)?;

        let decision_timeout = Duration::from_secs(snapshot.ir().runtime.decision_timeout_seconds);
        let presentation_registry = std::sync::Arc::new(
            arc::DecisionPresentationRegistry::with_durable_claim_store(state_store.clone()),
        );

        let decision_provider = std::sync::Arc::new(arc::CliDecisionProvider::new(target));
        let mut session = ArcRuntimeSession::from_trusted_snapshot(session_id.clone(), snapshot)
            .with_probe_runner(std::sync::Arc::new(arc::WorkspaceProbeRunner::new(
                workspace_root.clone(),
            )))
            .with_decision_provider(decision_provider)
            .with_state_store(state_store.clone());
        let decision_coordinator = GuardExecutionCoordinator::new(state_store.clone());

        match event_type {
            HookEventArg::PreToolUse => {
                if is_codex {
                    let input: CodexPreToolUseInput = serde_json::from_str(&stdin_input)
                        .with_context(|| "Failed parsing CodexPreToolUseInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    CodexAdapter::validate_pre_tool_use_input(&input)
                        .with_context(|| "Failed validating CodexPreToolUseInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    let event = CodexAdapter::pre_tool_use_to_event(&input, 1);
                    let operation = arc::CurrentOperation::from(&event);
                    let event_id = event.event_id.clone();
                    let eval_result = evaluate_guard_with_observability(
                        &mut session,
                        event,
                        &journal,
                        &observed,
                    )?;
                    let mut interactive_request =
                        interactive_decision_request_from_evaluation_result(
                            &eval_result,
                            arc::ProviderTarget::Codex,
                            arc::ArcEventType::ToolCall,
                            &event_id,
                            &invocation_id,
                            Some(operation),
                            Some(format!("{} {}", input.tool_name, input.tool_input)),
                            "this exact tool call once",
                        )?;
                    let interactive_context = interactive_request
                        .as_mut()
                        .map(|request| {
                            prepare_interactive_resolution(
                                request,
                                &eval_result,
                                &decision_coordinator,
                                &workspace_id,
                                &session_id,
                                observed.turn_id.as_deref(),
                                &invocation_id,
                            )
                        })
                        .transpose()?;
                    let output = if let Some(request) = interactive_request {
                        let dispatch = dispatch_interactive_decision(
                            request,
                            &HookDecisionContext {
                                decision_ui,
                                decision_timeout,
                                journal: &journal,
                                observed: &observed,
                                presentation_registry: std::sync::Arc::clone(
                                    &presentation_registry,
                                ),
                            },
                        )?;
                        match dispatch {
                            arc::InteractiveDecisionDispatch::CapabilityOnly { capability } => {
                                if let Some(context) = interactive_context.as_ref() {
                                    abandon_interactive_resolution(&decision_coordinator, context)?;
                                }
                                CodexAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
                                    &eval_result,
                                    &capability,                                )?
                            }
                            arc::InteractiveDecisionDispatch::Presented {
                                capability,
                                resolution,
                            } => {
                                let applied = arc::apply_interactive_resolution(
                                    &resolution,
                                    resolution
                                        .request()
                                        .evaluation_result()
                                        .unwrap_or(&eval_result),
                                    &decision_coordinator,
                                    interactive_context.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("presented decision has no durable context")
                                    })?,
                                )?;
                                let guard_id = resolution.request().guard().guard_id();
                                let user_message = resolution
                                    .user_message()
                                    .map(|message| format!(" User message: {message}"))
                                    .unwrap_or_default();
                                let message_feedback = message_feedback_for_tool_call(&eval_result)
                                    .map(|feedback| format!(" {feedback}"))
                                    .unwrap_or_default();
                                let deny_reason = match &applied.directive {
                                    arc::AppliedDecisionDirective::Allow { .. } => String::new(),
                                    arc::AppliedDecisionDirective::Deny { .. } => {
                                        format!(
                                            "The user denied the Arc policy request.{user_message}{message_feedback}"
                                        )
                                    }
                                    arc::AppliedDecisionDirective::Retry { reason } => {
                                        format!(
                                            "The Arc policy request remained unresolved ({reason:?}); the current call was blocked without recording a user denial.{user_message}{message_feedback}"
                                        )
                                    }
                                };
                                CodexAdapter::embedded_decision_to_pre_tool_use_output(
                                    &capability,
                                    resolution.portable_decision(),
                                    format!(
                                        "Arc decision received: allow. guard_id={guard_id}; transport=arc_embedded_ui; invocation_id={invocation_id}; scope=exact_pending_tool_call_once. The user allowed only this exact pending call; modified arguments or later calls require a new decision.{user_message}{message_feedback}"
                                    ),
                                    deny_reason,
                                )?
                            }
                        }
                    } else {
                        CodexAdapter::evaluation_result_to_pre_tool_use_output(&eval_result)?
                    };
                    session.record_feedback_prepared(
                        &journal,
                        &observed,
                        &eval_result.failure_bundle,
                    )?;
                    session.release_activation_cache(&journal, &observed)?;
                    write_hook_output(&journal, &observed, &output)?;
                } else {
                    let input: AgyPreToolUseInput = serde_json::from_str(&stdin_input)
                        .with_context(|| "Failed parsing AgyPreToolUseInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    AgyAdapter::validate_pre_tool_use_input(&input)
                        .with_context(|| "Failed validating AgyPreToolUseInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    let event = AgyAdapter::pre_tool_use_to_event(&input, 1);
                    let operation = arc::CurrentOperation::from(&event);
                    let event_id = event.event_id.clone();
                    let eval_result = evaluate_guard_with_observability(
                        &mut session,
                        event,
                        &journal,
                        &observed,
                    )?;
                    let mut interactive_request =
                        interactive_decision_request_from_evaluation_result(
                            &eval_result,
                            arc::ProviderTarget::Gemini,
                            arc::ArcEventType::ToolCall,
                            &event_id,
                            &invocation_id,
                            Some(operation),
                            Some(format!("{} {}", input.tool_call.name, input.tool_call.args)),
                            "this exact tool call once",
                        )?;
                    let interactive_context = interactive_request
                        .as_mut()
                        .map(|request| {
                            prepare_interactive_resolution(
                                request,
                                &eval_result,
                                &decision_coordinator,
                                &workspace_id,
                                &session_id,
                                observed.turn_id.as_deref(),
                                &invocation_id,
                            )
                        })
                        .transpose()?;
                    let output = if let Some(request) = interactive_request {
                        let dispatch = dispatch_interactive_decision(
                            request,
                            &HookDecisionContext {
                                decision_ui,
                                decision_timeout,
                                journal: &journal,
                                observed: &observed,
                                presentation_registry: std::sync::Arc::clone(
                                    &presentation_registry,
                                ),
                            },
                        )?;
                        match dispatch {
                            arc::InteractiveDecisionDispatch::CapabilityOnly { capability } => {
                                if let Some(context) = interactive_context.as_ref() {
                                    abandon_interactive_resolution(&decision_coordinator, context)?;
                                }
                                AgyAdapter::evaluation_result_to_pre_tool_use_output_with_resolution(
                                    &eval_result,
                                    &capability,                                )?
                            }
                            arc::InteractiveDecisionDispatch::Presented {
                                capability,
                                resolution,
                            } => {
                                let _applied = arc::apply_interactive_resolution(
                                    &resolution,
                                    resolution
                                        .request()
                                        .evaluation_result()
                                        .unwrap_or(&eval_result),
                                    &decision_coordinator,
                                    interactive_context.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("presented decision has no durable context")
                                    })?,
                                )?;
                                let guard_id = resolution.request().guard().guard_id();
                                let reason = agy_embedded_ui_pre_tool_use_reason(
                                    &resolution.portable_decision(),
                                    guard_id,
                                    resolution.user_message(),
                                );
                                let reason = message_feedback_for_tool_call(&eval_result)
                                    .map(|feedback| format!("{reason} {feedback}"))
                                    .unwrap_or(reason);
                                AgyAdapter::embedded_decision_to_pre_tool_use_output(
                                    &capability,
                                    resolution.portable_decision(),
                                    reason,
                                )?
                            }
                        }
                    } else {
                        AgyAdapter::evaluation_result_to_pre_tool_use_output(&eval_result)?
                    };
                    session.record_feedback_prepared(
                        &journal,
                        &observed,
                        &eval_result.failure_bundle,
                    )?;
                    session.release_activation_cache(&journal, &observed)?;
                    write_hook_output(&journal, &observed, &output)?;
                }
            }
            HookEventArg::Stop => {
                if is_codex {
                    let input: CodexStopInput = serde_json::from_str(&stdin_input)
                        .with_context(|| "Failed parsing CodexStopInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    let event = CodexAdapter::stop_to_event(&input, 1);
                    let eval_result = evaluate_guard_with_observability(
                        &mut session,
                        event,
                        &journal,
                        &observed,
                    )?;
                    let stop_outcome = coordinate_stop(
                        &resolved_ir_path,
                        &CodexAdapter::stop_activation(&input, &invocation_id),
                        &eval_result,
                        &invocation_id,
                        &HookDecisionContext {
                            decision_ui,
                            decision_timeout,
                            journal: &journal,
                            observed: &observed,
                            presentation_registry: std::sync::Arc::clone(&presentation_registry),
                        },
                    )?;
                    let output = CodexAdapter::lifecycle_stop_to_output(
                        stop_outcome,
                        &eval_result,
                        &invocation_id,
                    )?;
                    session.record_feedback_prepared(
                        &journal,
                        &observed,
                        &eval_result.failure_bundle,
                    )?;
                    session.release_activation_cache(&journal, &observed)?;
                    write_hook_output(&journal, &observed, &output)?;
                } else {
                    let input: AgyStopInput = serde_json::from_str(&stdin_input)
                        .with_context(|| "Failed parsing AgyStopInput from stdin")
                        .context(HookFailureContext::InvalidPayload)?;
                    let event = AgyAdapter::stop_to_event(&input, 1);
                    let eval_result = evaluate_guard_with_observability(
                        &mut session,
                        event,
                        &journal,
                        &observed,
                    )?;
                    let stop_outcome = coordinate_stop(
                        &resolved_ir_path,
                        &AgyAdapter::stop_activation(&input, &invocation_id),
                        &eval_result,
                        &invocation_id,
                        &HookDecisionContext {
                            decision_ui,
                            decision_timeout,
                            journal: &journal,
                            observed: &observed,
                            presentation_registry: std::sync::Arc::clone(&presentation_registry),
                        },
                    )?;
                    let output = AgyAdapter::lifecycle_stop_to_output(
                        stop_outcome,
                        &eval_result,
                        &invocation_id,
                    )?;
                    session.record_feedback_prepared(
                        &journal,
                        &observed,
                        &eval_result.failure_bundle,
                    )?;
                    session.release_activation_cache(&journal, &observed)?;
                    write_hook_output(&journal, &observed, &output)?;
                }
            }
            HookEventArg::SessionStart => {
                if !is_codex {
                    validate_hook_provider_event(target, event_type)?;
                }
                let input: CodexSessionStartInput = serde_json::from_str(&stdin_input)
                    .with_context(|| "Failed parsing CodexSessionStartInput from stdin")
                    .context(HookFailureContext::InvalidPayload)?;
                let event = CodexAdapter::session_start_to_event(&input, 1);
                let eval_result =
                    evaluate_guard_with_observability(&mut session, event, &journal, &observed)?;
                let output = match eval_result.effective_disposition {
                    arc::EffectiveDisposition::Ask => {
                        let guard_id = eval_result
                            .failure_bundle
                            .failed_guards
                            .first()
                            .map(|g| g.guard_id.as_str())
                            .unwrap_or("unknown");
                        arc::CodexSessionStartOutput::abort(Some(format!(
                            "Arc rejected invalid compiled policy: lifecycle start guard '{guard_id}' cannot use action ask."
                        )))
                    }
                    _ => CodexAdapter::evaluation_result_to_session_start_output(&eval_result)?,
                };
                session.record_feedback_prepared(
                    &journal,
                    &observed,
                    &eval_result.failure_bundle,
                )?;
                session.release_activation_cache(&journal, &observed)?;
                write_hook_output(&journal, &observed, &output)?;
            }
            HookEventArg::PreInvocation => {
                if is_codex {
                    validate_hook_provider_event(target, event_type)?;
                }
                let input: AgyPreInvocationInput = serde_json::from_str(&stdin_input)
                    .with_context(|| "Failed parsing AgyPreInvocationInput from stdin")
                    .context(HookFailureContext::InvalidPayload)?;
                let output = if let Some(event) = AgyAdapter::pre_invocation_to_event(&input, 1) {
                    let eval_result = evaluate_guard_with_observability(
                        &mut session,
                        event,
                        &journal,
                        &observed,
                    )?;
                    if matches!(
                        eval_result.effective_disposition,
                        arc::EffectiveDisposition::Ask
                    ) {
                        bail!(
                            "Antigravity cannot enforce lifecycle ask on start: PreInvocation has no blocking decision output"
                        );
                    }
                    let out = AgyAdapter::evaluation_result_to_pre_invocation_output(&eval_result)?;
                    session.record_feedback_prepared(
                        &journal,
                        &observed,
                        &eval_result.failure_bundle,
                    )?;
                    session.release_activation_cache(&journal, &observed)?;
                    out
                } else {
                    arc::runtime::adapter::agy::AgyPreInvocationOutput::allow()
                };
                write_hook_output(&journal, &observed, &output)?;
            }
        }

        Ok(())
    })();

    if let Err(error) = &hook_result {
        let reason_code = hook_failure_reason_code(error);
        append_observation(
            &journal,
            &observed,
            "HookFailed",
            "error",
            Some(reason_code.into()),
            Some(started.elapsed().as_millis() as i64),
            serde_json::json!({
                "capture": "metadata",
                "event": event_type.as_str(),
                "failure_class": reason_code
            }),
        );
    }
    hook_result
}

#[allow(clippy::too_many_arguments)]
fn interactive_decision_request_from_evaluation_result(
    eval_result: &arc::ArcEvaluationResult,
    provider: arc::ProviderTarget,
    event: arc::ArcEventType,
    event_id: &str,
    invocation_id: &str,
    operation: Option<arc::CurrentOperation>,
    operation_display: Option<String>,
    scope: &str,
) -> Result<Option<arc::InteractiveDecisionRequest>> {
    arc::interactive_decision_request_from_evaluation_result(
        eval_result,
        provider,
        event,
        event_id,
        invocation_id,
        operation,
        operation_display,
        scope,
    )
}

fn prepare_interactive_resolution(
    request: &mut arc::InteractiveDecisionRequest,
    eval_result: &arc::ArcEvaluationResult,
    coordinator: &GuardExecutionCoordinator,
    workspace_id: &str,
    session_id: &str,
    turn_id: Option<&str>,
    invocation_id: &str,
) -> Result<InteractiveResolutionContext> {
    let authorization_items = request.exact_authorizations().unwrap_or(&[]);
    let operation = request
        .operation()
        .ok_or_else(|| anyhow::anyhow!("interactive request has no current operation"))?;
    let tool = operation
        .tool
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("interactive request operation has no tool"))?;
    let authorization_context = if authorization_items.is_empty() {
        None
    } else {
        Some(ExactAuthorizationContext::for_authorizations(
            &eval_result.failure_bundle.event_id,
            tool,
            workspace_id,
            request.provider().as_str(),
            session_id,
            invocation_id,
            &eval_result.report.report_fingerprint,
            &eval_result.failure_bundle.bundle_fingerprint,
            authorization_items,
        )?)
    };

    let mut guard_ids = request
        .guards()
        .iter()
        .map(|guard| guard.guard_id().to_owned())
        .collect::<BTreeSet<_>>();
    guard_ids.extend(
        authorization_items
            .iter()
            .map(|authorization| authorization.guard_id.clone()),
    );
    let mut keys = Vec::with_capacity(guard_ids.len());
    let mut pending_correlation = None;
    let mut pending_targets = Vec::with_capacity(guard_ids.len());
    let mut expires_at_unix_ms = i64::MAX;
    for guard_id in guard_ids {
        let guard_context = request
            .guards()
            .iter()
            .find(|guard| guard.guard_id() == guard_id);
        let guard_result = eval_result
            .report
            .guard_results
            .iter()
            .find(|result| result.guard_id == guard_id);
        let is_ask_violation = guard_result.is_some_and(|result| {
            result.configured_action == arc::ActionType::Ask
                && matches!(result.state, arc::GuardResultState::Violated { .. })
        });
        let key = GuardExecutionKey {
            workspace_id: workspace_id.to_owned(),
            session_id: session_id.to_owned(),
            turn_id: turn_id.map(str::to_owned),
            guard_id: guard_id.clone(),
            activation: GuardActivation::ToolCall,
            subject_id: Some(eval_result.failure_bundle.event_id.clone()),
        };
        let directive = if is_ask_violation {
            coordinator.coordinate(CoordinationInput {
                key: key.clone(),
                invocation_id: invocation_id.to_owned(),
                signals: ProviderSignals {
                    reentry: ReentryKind::FirstInvocation,
                    ..ProviderSignals::default()
                },
                evaluation: EvaluationSnapshot::Violated {
                    feedback: Some(
                        guard_context
                            .and_then(|guard| guard.configured_feedback())
                            .unwrap_or("Arc guard requires a decision.")
                            .to_owned(),
                    ),
                },
                violation_handling: ViolationHandling::RequireDecision,
            })?
        } else if authorization_items
            .iter()
            .any(|authorization| authorization.guard_id == guard_id)
        {
            coordinator.coordinate_authorization(
                key.clone(),
                invocation_id,
                &eval_result.failure_bundle.bundle_fingerprint,
            )?
        } else {
            bail!(
                "interactive guard '{}' is not represented by a durable violation or authorization",
                guard_id
            );
        };
        let pending = directive.decision_request.ok_or_else(|| {
            anyhow::anyhow!("interactive guard did not produce a durable pending decision")
        })?;
        expires_at_unix_ms = expires_at_unix_ms.min(pending.expires_at_unix_ms);
        if pending_correlation.is_none() {
            pending_correlation = Some(arc::DecisionCorrelation::new(
                pending.decision_id.clone(),
                pending.execution_id.clone(),
                Some(invocation_id.to_owned()),
            )?);
        }
        pending_targets.push(arc::InteractivePendingTarget {
            key: key.clone(),
            decision_id: pending.decision_id,
            execution_id: pending.execution_id,
        });
        keys.push(key);
    }

    let correlation = pending_correlation
        .ok_or_else(|| anyhow::anyhow!("interactive request contains no durable guard targets"))?;
    request.set_correlation(correlation);
    Ok(InteractiveResolutionContext {
        keys,
        pending_targets,
        owner_invocation_id: invocation_id.to_owned(),
        resolution_invocation_id: invocation_id.to_owned(),
        expires_at_unix_ms,
        receipt_received_at_unix_ms: unix_time_ms(),
        authorization_context,
    })
}

fn abandon_interactive_resolution(
    coordinator: &GuardExecutionCoordinator,
    context: &InteractiveResolutionContext,
) -> Result<()> {
    for pending_target in &context.pending_targets {
        coordinator.abandon_decision(
            &pending_target.key,
            &context.owner_invocation_id,
            &pending_target.decision_id,
            &pending_target.execution_id,
        )?;
    }
    Ok(())
}

fn dispatch_interactive_decision(
    request: arc::InteractiveDecisionRequest,
    context: &HookDecisionContext<'_>,
) -> Result<arc::InteractiveDecisionDispatch> {
    let orchestrator = arc::InteractiveDecisionOrchestrator::with_registry(
        OsTarget::host()?,
        capability_decision_ui(context.decision_ui),
        context.decision_timeout,
        std::sync::Arc::clone(&context.presentation_registry),
    );
    dispatch_interactive_decision_with_orchestrator(request, &orchestrator, context)
}

fn dispatch_interactive_decision_with_orchestrator(
    request: arc::InteractiveDecisionRequest,
    orchestrator: &arc::InteractiveDecisionOrchestrator,
    context: &HookDecisionContext<'_>,
) -> Result<arc::InteractiveDecisionDispatch> {
    let presentation_started = std::time::Instant::now();
    append_observation(
        context.journal,
        context.observed,
        "DecisionPresentationRequested",
        "info",
        None,
        None,
        serde_json::json!({
            "presentation_id": request.presentation_id(),
            "provider": request.provider(),
            "event": request.event(),
            "guard_id": request.guard().guard_id(),
            "scope": request.scope(),
            "transport_requested": "arc_embedded_ui",
        }),
    );
    let dispatch = match orchestrator.dispatch(request) {
        Ok(dispatch) => dispatch,
        Err(error) => {
            append_observation(
                context.journal,
                context.observed,
                "DecisionPresentationFailed",
                "error",
                Some("presentation_dispatch_failed".into()),
                Some(presentation_started.elapsed().as_millis() as i64),
                serde_json::json!({ "capture": "metadata" }),
            );
            return Err(error.context(HookFailureContext::DecisionTransport));
        }
    };
    append_observation(
        context.journal,
        context.observed,
        "DecisionPresentationCompleted",
        "info",
        None,
        Some(presentation_started.elapsed().as_millis() as i64),
        serde_json::json!({
            "presented": dispatch.resolution().is_some(),
            "transport": dispatch.capability().decision_transport,
            "effective_action": dispatch.capability().effective_action,
        }),
    );
    append_observation(
        context.journal,
        context.observed,
        "DecisionTransportResolved",
        "info",
        None,
        None,
        serde_json::json!({
            "capability": dispatch.capability(),
            "transport": dispatch.capability().decision_transport,
            "effective_action": dispatch.capability().effective_action,
            "mechanism": dispatch.capability().mechanism,
        }),
    );
    if let Some(resolution) = dispatch.resolution() {
        append_observation(
            context.journal,
            context.observed,
            "DecisionReceived",
            "info",
            None,
            None,
            serde_json::json!({
                "metadata": resolution.metadata(),
                "user_message_present": resolution.user_message().is_some(),
                "scope": resolution.request().scope(),
                "guard_id": resolution.request().guard().guard_id(),
            }),
        );
    }
    Ok(dispatch)
}

fn agy_embedded_ui_pre_tool_use_reason(
    decision: &arc::decision_ui::PortableDecision,
    guard_id: &str,
    user_message: Option<&str>,
) -> String {
    let user_message = user_message
        .map(|message| format!(" User message: {message}"))
        .unwrap_or_default();
    format!("Arc decision {decision:?} via arc_embedded_ui for guard {guard_id}.{user_message}")
}

struct LifecycleAskContext<'a> {
    event: &'a str,
    guard_id: &'a str,
    prompt: Option<&'a str>,
    failure_context: &'a arc::GuardFailureContext,
    failure_contexts: &'a [arc::GuardFailureContext],
    invocation_id: &'a str,
    correlation: Option<arc::DecisionCorrelation>,
}

fn request_lifecycle_ask(
    provider: arc::ProviderTarget,
    lifecycle: LifecycleAskContext<'_>,
    context: &HookDecisionContext<'_>,
) -> Result<(arc::DialogResponse, arc::CapabilityResolution)> {
    if lifecycle.event != "end" {
        bail!("interactive lifecycle decisions are supported only for end guards");
    }

    if lifecycle.failure_context.guard_id() != lifecycle.guard_id {
        bail!(
            "Arc lifecycle guard context mismatch: requested '{}' versus context '{}'",
            lifecycle.guard_id,
            lifecycle.failure_context.guard_id()
        );
    }

    let guards = if !lifecycle.failure_contexts.is_empty() {
        lifecycle.failure_contexts.to_vec()
    } else {
        vec![lifecycle.failure_context.clone()]
    };
    let prompt_text = if guards.len() > 1 {
        let guard_names = guards
            .iter()
            .map(|g| format!("'{}'", g.guard_id()))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Arc guards {} are not satisfied. Allow the agent to attempt remediation before stopping?\n\n{}",
            guard_names,
            lifecycle
                .prompt
                .unwrap_or("The completion requirement is currently unmet.")
        )
    } else {
        format!(
            "Arc guard '{}' is not satisfied. Allow the agent to attempt remediation before stopping?\n\n{}",
            lifecycle.guard_id,
            lifecycle
                .prompt
                .unwrap_or("The completion requirement is currently unmet.")
        )
    };

    let request = arc::InteractiveDecisionRequest::with_guards(
        provider,
        arc::ArcEventType::End,
        arc::ActionType::Ask,
        arc::new_invocation_id(),
        lifecycle.invocation_id,
        guards,
        prompt_text,
        None,
        Some(format!("lifecycle:{}", lifecycle.event)),
        "authorize remediation for this failed completion guard",
        lifecycle.correlation,
    )?;
    let dispatch = dispatch_interactive_decision(request, context)?;
    match dispatch {
        arc::InteractiveDecisionDispatch::Presented {
            capability,
            resolution,
        } => Ok((resolution.to_dialog_response(), capability)),
        arc::InteractiveDecisionDispatch::CapabilityOnly { capability } => {
            bail!("{}", capability.mechanism)
        }
    }
}

struct HookDecisionContext<'a> {
    decision_ui: DecisionUiArg,
    decision_timeout: Duration,
    journal: &'a Option<ObservabilityJournal>,
    observed: &'a HookObservationContext,
    presentation_registry: std::sync::Arc<arc::DecisionPresentationRegistry>,
}

type HookObservationContext = arc::HookObservationContext;

fn append_observation(
    journal: &Option<ObservabilityJournal>,
    context: &HookObservationContext,
    event_type: &str,
    level: &str,
    reason_code: Option<String>,
    duration_ms: Option<i64>,
    details: serde_json::Value,
) {
    if let Some(journal) = journal {
        let _ = journal.append(NewObservabilityEvent {
            event_type: event_type.into(),
            level: level.into(),
            provider: Some(context.provider.clone()),
            workspace_id: context.workspace_id.clone(),
            session_id: Some(context.session_id.clone()),
            turn_id: context.turn_id.clone(),
            invocation_id: Some(context.invocation_id.clone()),
            reason_code,
            duration_ms,
            details,
            ..Default::default()
        });
    }
}

fn evaluate_guard_with_observability(
    session: &mut ArcRuntimeSession,
    event: arc::ArcEvent,
    journal: &Option<ObservabilityJournal>,
    observed: &HookObservationContext,
) -> Result<arc::ArcEvaluationResult> {
    arc::evaluate_guard_with_observability(session, event, journal, observed)
}

fn write_hook_output<T: serde::Serialize>(
    journal: &Option<ObservabilityJournal>,
    context: &HookObservationContext,
    output: &T,
) -> Result<()> {
    let value = serde_json::to_value(output)?;
    let encoded = serde_json::to_vec(&value)?;
    let output_kind = value
        .get("decision")
        .or_else(|| value.get("continue"))
        .or_else(|| {
            value
                .get("hookSpecificOutput")
                .and_then(|nested| nested.get("permissionDecision"))
        })
        .cloned();
    append_observation(
        journal,
        context,
        "ProviderOutput",
        "info",
        None,
        None,
        serde_json::json!({
            "output_bytes": encoded.len(),
            "output_sha256": hex::encode(Sha256::digest(&encoded)),
            "output_kind": output_kind,
            "capture": "metadata"
        }),
    );
    println!("{}", serde_json::to_string(output)?);
    Ok(())
}

fn extract_optional_string(input: &str, keys: &[&str]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(input).ok()?;
    keys.iter()
        .find_map(|key| value.get(*key)?.as_str().map(str::to_owned))
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn message_feedback_for_tool_call(eval_result: &arc::ArcEvaluationResult) -> Option<String> {
    let feedback = eval_result
        .failure_bundle
        .failed_guards
        .iter()
        .filter(|guard| guard.configured_action == arc::ActionType::Message && !guard.faulted)
        .filter_map(|guard| {
            guard.configured_feedback.clone().or_else(|| {
                let findings = guard
                    .causes
                    .iter()
                    .map(|cause| {
                        cause
                            .auditor_findings
                            .as_deref()
                            .unwrap_or(&cause.summary)
                            .to_owned()
                    })
                    .collect::<Vec<_>>();
                (!findings.is_empty()).then(|| findings.join("; "))
            })
        })
        .collect::<Vec<_>>();
    (!feedback.is_empty()).then(|| format!("Arc Message feedback: {}", feedback.join("; ")))
}

fn coordinate_stop(
    ir_path: &Path,
    activation: &arc::runtime::execution::LifecycleStopActivation,
    eval_result: &arc::ArcEvaluationResult,
    invocation_id: &str,
    decision_context: &HookDecisionContext<'_>,
) -> Result<arc::runtime::execution::LifecycleStopOutcome> {
    let state_path = default_state_database_path()?;
    let store = std::sync::Arc::new(SqliteStateStore::open(&state_path)?);
    let canonical_root = canonical_workspace_root(ir_path)?;
    let workspace_id = store.resolve_workspace_id(&canonical_root)?;
    let coordinator = GuardExecutionCoordinator::new(store);
    let capability = arc::resolve_capability(arc::CapabilityContext::cli(
        activation.provider,
        OsTarget::host()?,
        arc::CapabilityEvent::End,
        arc::ActionType::Ask,
        capability_decision_ui(decision_context.decision_ui),
    ));
    arc::runtime::execution::coordinate_lifecycle_stop(
        &coordinator,
        &arc::runtime::execution::LifecycleStopContext {
            activation,
            workspace_id: &workspace_id,
            decision_transport_available: capability.decision_transport.is_some(),
        },
        eval_result,
        |request| {
            request_lifecycle_ask(
                activation.provider,
                LifecycleAskContext {
                    event: "end",
                    guard_id: request.guard_id,
                    prompt: request.primary_context.configured_feedback(),
                    failure_context: request.primary_context,
                    failure_contexts: request.failure_contexts,
                    invocation_id,
                    correlation: Some(request.correlation),
                },
                decision_context,
            )
        },
        |guard_id, coordination_id, directive, available| {
            append_stop_coordination_events(
                &state_path,
                activation,
                &workspace_id,
                guard_id,
                coordination_id,
                directive,
                available,
            )
        },
    )
}

fn append_stop_coordination_events(
    state_path: &Path,
    activation: &arc::runtime::execution::LifecycleStopActivation,
    workspace_id: &str,
    guard_id: &str,
    invocation_id: &str,
    directive: &RuntimeDirective,
    decision_transport_available: bool,
) {
    let Ok(journal) = ObservabilityJournal::open(state_path) else {
        return;
    };
    let reason = format!("{:?}", directive.reason_code);
    let disposition = format!("{:?}", directive.disposition);
    let base = NewObservabilityEvent {
        level: if matches!(directive.disposition, RuntimeDisposition::Proceed) {
            "info".into()
        } else {
            "warn".into()
        },
        provider: Some(activation.provider.as_str().into()),
        workspace_id: Some(workspace_id.to_owned()),
        session_id: Some(activation.session_id.clone()),
        turn_id: activation.turn_id.clone(),
        execution_id: Some(directive.execution_id.clone()),
        invocation_id: Some(invocation_id.to_owned()),
        guard_id: Some(guard_id.to_owned()),
        reason_code: Some(reason.clone()),
        details: serde_json::Value::Null,
        ..Default::default()
    };
    let mut transition = base.clone();
    transition.event_type = "StateTransition".into();
    transition.details = serde_json::json!({
        "disposition": disposition,
        "attempts": directive.attempts,
        "evidence_fingerprint": directive.evidence_fingerprint
    });
    let _ = journal.append(transition);

    if !decision_transport_available
        && matches!(
            directive.disposition,
            RuntimeDisposition::RequestDecision
                | RuntimeDisposition::RequestAuthorization
                | RuntimeDisposition::Suspend
        )
    {
        let capability = if directive.disposition == RuntimeDisposition::Suspend {
            "lifecycle_suspend"
        } else {
            "lifecycle_structured_decision"
        };
        let mut provider_capability = base.clone();
        provider_capability.event_type = "ProviderCapability".into();
        provider_capability.level = "warn".into();
        provider_capability.details = serde_json::json!({
            "capability": capability,
            "support": "unsupported",
            "provider": activation.provider.as_str(),
            "event": "stop"
        });
        let _ = journal.append(provider_capability);

        let mut degraded = base.clone();
        degraded.event_type = "CapabilityDegraded".into();
        degraded.level = "warn".into();
        degraded.details = serde_json::json!({
            "capability": capability,
            "requested_disposition": disposition,
            "effective_disposition": "Abort",
            "provider_output": { "continue": false },
            "provider_acknowledgement": "not_observable"
        });
        let _ = journal.append(degraded);
    }

    let mut emitted = base;
    emitted.event_type = "DirectiveEmitted".into();
    emitted.details = serde_json::json!({"disposition": disposition});
    let _ = journal.append(emitted);
}

fn extract_session_id_from_stdin(stdin_raw: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdin_raw) {
        if let Some(id) = v
            .get("conversationId")
            .or_else(|| v.get("conversation_id"))
            .or_else(|| v.get("sessionId"))
            .or_else(|| v.get("session_id"))
            .and_then(|s| s.as_str())
        {
            return Some(id.to_string());
        }
    }
    None
}

fn detect_codex_format(stdin_raw: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdin_raw) {
        if v.get("tool_name").is_some()
            || v.get("toolName").is_some()
            || v.get("hook_event_name").is_some()
            || v.get("hookEventName").is_some()
            || v.get("tool_input").is_some()
            || v.get("toolInput").is_some()
            || v.get("tool_use_id").is_some()
            || v.get("toolUseId").is_some()
            || v.get("turn_id").is_some()
            || v.get("turnId").is_some()
            || v.get("stop_hook_active").is_some()
            || v.get("stopHookActive").is_some()
            || v.get("rollout_path").is_some()
            || v.get("rolloutPath").is_some()
        {
            return true;
        }
    }
    false
}

fn infer_provider_from_ir_path(ir_path: Option<&Path>) -> Option<ProviderTarget> {
    let path = ir_path?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        if name.eq_ignore_ascii_case(".codex") {
            return Some(ProviderTarget::Codex);
        }
        if name.eq_ignore_ascii_case(".agents") {
            return Some(ProviderTarget::Gemini);
        }
    }
    None
}

fn detect_agy_format(stdin_raw: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdin_raw) {
        if v.get("toolCall").is_some()
            || v.get("stepIdx").is_some()
            || v.get("conversationId").is_some()
            || v.get("conversation_id").is_some()
            || v.get("modelName").is_some()
            || v.get("invocationNum").is_some()
            || v.get("executionNum").is_some()
            || v.get("terminationReason").is_some()
            || v.get("fullyIdle").is_some()
            || v.get("workspaceDirs").is_some()
            || v.get("agentMode").is_some()
        {
            return true;
        }
    }
    false
}

fn resolve_hook_target(
    event_type: HookEventArg,
    ir_path: Option<&Path>,
    provider_hint: Option<HookProviderArg>,
    stdin_raw: &str,
) -> ProviderTarget {
    if let Some(provider) = provider_hint {
        return provider.target();
    }
    if let Some(target) = infer_provider_from_ir_path(ir_path) {
        return target;
    }
    if detect_codex_format(stdin_raw) {
        return ProviderTarget::Codex;
    }
    if detect_agy_format(stdin_raw) {
        return ProviderTarget::Gemini;
    }
    match event_type {
        HookEventArg::SessionStart => ProviderTarget::Codex,
        HookEventArg::PreInvocation | HookEventArg::PreToolUse | HookEventArg::Stop => {
            ProviderTarget::Gemini
        }
    }
}

fn validate_hook_provider_event(target: ProviderTarget, event_type: HookEventArg) -> Result<()> {
    if event_type.supports_provider(target) {
        return Ok(());
    }
    let expected_event = match target {
        ProviderTarget::Codex => "session-start",
        ProviderTarget::Gemini => "pre-invocation",
        ProviderTarget::Claude | ProviderTarget::OpenCode => "pre-tool-use",
    };
    Err(anyhow::anyhow!(
        "Unsupported hook event '{}' for provider '{}': provider '{}' requires '{}', pre-tool-use, or stop",
        event_type.as_str(),
        target.as_str(),
        target.as_str(),
        expected_event
    ).context(HookFailureContext::UnsupportedProviderEvent))
}

fn should_bypass_recursive_agy_hook(event_type: HookEventArg, stdin_input: &str) -> bool {
    match event_type {
        HookEventArg::PreToolUse => true,
        HookEventArg::PreInvocation | HookEventArg::Stop => {
            let Some(session_id) = extract_session_id_from_stdin(stdin_input) else {
                return false;
            };
            let transcript_path =
                extract_optional_string(stdin_input, &["transcriptPath", "transcript_path"])
                    .map(PathBuf::from);
            let context = arc::SessionContextExtractor::extract_from_session_id_with_provider_path(
                &session_id,
                Some(ProviderTarget::Gemini),
                transcript_path.as_deref(),
            );
            arc::is_auditor_session_intent(&context.user_intent)
        }
        HookEventArg::SessionStart => false,
    }
}

fn emit_fail_safe_allow(is_codex: bool) {
    if is_codex {
        let out = arc::CodexPreToolUseOutput::allow();
        let _ = serde_json::to_string(&out).map(|s| println!("{}", s));
    } else {
        println!("{}", serde_json::json!({"decision": "allow"}));
    }
}

fn emit_fail_safe_allow_for_event(event_type: HookEventArg, is_codex: bool) {
    match event_type {
        HookEventArg::PreToolUse => emit_fail_safe_allow(is_codex),
        HookEventArg::PreInvocation => {
            let out = arc::runtime::adapter::agy::AgyPreInvocationOutput::allow();
            if let Ok(serialized) = serde_json::to_string(&out) {
                println!("{serialized}");
            } else {
                println!("{{}}");
            }
        }
        HookEventArg::Stop => {
            if is_codex {
                let out = arc::CodexStopOutput::allow();
                if let Ok(serialized) = serde_json::to_string(&out) {
                    println!("{serialized}");
                }
            } else {
                let out = arc::runtime::adapter::agy::AgyStopOutput::stop();
                if let Ok(serialized) = serde_json::to_string(&out) {
                    println!("{serialized}");
                } else {
                    println!("{}", serde_json::json!({"decision": "stop"}));
                }
            }
        }
        HookEventArg::SessionStart => {
            let out = arc::CodexSessionStartOutput::allow();
            if let Ok(serialized) = serde_json::to_string(&out) {
                println!("{serialized}");
            }
        }
    }
}

const PUBLIC_HOOK_FAILURE_REASON: &str =
    "[ARC-HOOK-001] Guard evaluation failed; see local Arc diagnostics.";

/// Typed context for failures at the hook's protocol and orchestration boundaries.
#[derive(Debug, Clone, Copy, thiserror::Error)]
enum HookFailureContext {
    #[error("unsupported provider hook event")]
    UnsupportedProviderEvent,
    #[error("invalid provider hook payload")]
    InvalidPayload,
    #[error("could not resolve trusted runtime IR")]
    IrResolution,
    #[error("interactive decision transport failed")]
    DecisionTransport,
}

fn hook_failure_reason_code(error: &anyhow::Error) -> &'static str {
    let boundary_code = match error.downcast_ref::<HookFailureContext>() {
        Some(HookFailureContext::UnsupportedProviderEvent) => Some("unsupported_provider_event"),
        Some(HookFailureContext::InvalidPayload) => Some("invalid_hook_payload"),
        Some(HookFailureContext::IrResolution) => Some("ir_resolution_failed"),
        Some(HookFailureContext::DecisionTransport) | None => None,
    };
    if let Some(code) = boundary_code {
        return code;
    }
    if error.is::<arc::PreventiveSecurityFaultError>() {
        return "invalid_hook_payload";
    }
    if let Some(decision) = error.downcast_ref::<arc::DecisionError>() {
        return match decision {
            arc::DecisionError::ExecutionFailed { .. } => "decision_provider_execution_failed",
            arc::DecisionError::SpawnFailed { .. } => "decision_provider_spawn_failed",
            arc::DecisionError::TimedOut { .. } => "decision_transport_timeout",
            arc::DecisionError::UnparseableResponse { .. } => "decision_provider_output_invalid",
            arc::DecisionError::SessionIntentUnavailable
            | arc::DecisionError::IsolationViolation { .. }
            | arc::DecisionError::ToolUseAttempted { .. }
            | arc::DecisionError::AuthenticationUnavailable { .. } => "decision_transport_failed",
        };
    }
    if let Some(completion) = error.downcast_ref::<arc::decision_ui::CompletionError>() {
        return match completion {
            arc::decision_ui::CompletionError::DeadlineExpired => "decision_transport_timeout",
            arc::decision_ui::CompletionError::AlreadyCompleted
            | arc::decision_ui::CompletionError::Emission(_) => "decision_transport_failed",
        };
    }
    if matches!(
        error.downcast_ref::<HookFailureContext>(),
        Some(HookFailureContext::DecisionTransport)
    ) {
        return if error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        }) {
            "decision_transport_timeout"
        } else {
            "decision_transport_failed"
        };
    }
    "hook_execution_failed"
}

fn emit_hook_failure(event_type: HookEventArg, is_codex: bool, reason: &str) {
    if let Some(value) = hook_failure_value(event_type, is_codex, reason) {
        println!("{value}");
    }
}

fn hook_failure_value(
    event_type: HookEventArg,
    is_codex: bool,
    reason: &str,
) -> Option<serde_json::Value> {
    if !is_codex {
        let output = match event_type {
            HookEventArg::Stop => {
                serde_json::to_value(arc::runtime::adapter::agy::AgyStopOutput::stop_with_reason(
                    Some(reason.to_string()),
                ))
            }
            HookEventArg::PreInvocation => serde_json::to_value(
                arc::runtime::adapter::agy::AgyPreInvocationOutput::abort(reason.to_string()),
            ),
            HookEventArg::PreToolUse | HookEventArg::SessionStart => serde_json::to_value(
                arc::runtime::adapter::agy::AgyPreToolUseOutput::deny(Some(reason.to_string())),
            ),
        };
        return output.ok();
    }

    let output = match event_type {
        HookEventArg::Stop => serde_json::to_value(arc::CodexStopOutput::abort(reason.to_string())),
        HookEventArg::SessionStart | HookEventArg::PreInvocation => serde_json::to_value(
            arc::CodexSessionStartOutput::abort(Some(reason.to_string())),
        ),
        HookEventArg::PreToolUse => {
            serde_json::to_value(arc::CodexPreToolUseOutput::deny(Some(reason.to_string())))
        }
    };
    output.ok()
}

fn resolve_ir_file(
    custom_path: Option<PathBuf>,
    stdin_raw: &str,
    prefer_codex: bool,
) -> Option<PathBuf> {
    if let Some(p) = custom_path {
        let expected_target = if prefer_codex {
            ProviderTarget::Codex
        } else {
            ProviderTarget::Gemini
        };
        if let Some(path_target) = infer_provider_from_ir_path(Some(p.as_path()))
            && path_target != expected_target
        {
            return None;
        }
        if p.exists() {
            return Some(p);
        }
    }

    // Provider artifacts can coexist and may be regenerated at different times.
    // Never let a Codex hook silently evaluate the Gemini/AGY IR (or vice versa).
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(path) = find_provider_ir(&cwd, prefer_codex) {
            return Some(path);
        }
    }

    // 2. Parse stdin JSON to inspect Cwd, cwd, AbsolutePath, TargetFile or workspaceDirs
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdin_raw) {
        let cwd_candidate = v
            .pointer("/toolCall/args/Cwd")
            .or_else(|| v.get("cwd"))
            .and_then(|c| c.as_str());

        if let Some(cwd_str) = cwd_candidate {
            let start = PathBuf::from(cwd_str);
            if let Some(path) = find_provider_ir(&start, prefer_codex) {
                return Some(path);
            }
        }
        if let Some(path_str) = v
            .pointer("/toolCall/args/AbsolutePath")
            .or_else(|| v.pointer("/toolCall/args/TargetFile"))
            .and_then(|c| c.as_str())
        {
            let start = PathBuf::from(path_str);
            if let Some(parent) = start.parent()
                && let Some(path) = find_provider_ir(parent, prefer_codex)
            {
                return Some(path);
            }
        }
        if let Some(ws_dirs) = v.get("workspaceDirs").and_then(|w| w.as_array()) {
            for ws in ws_dirs {
                if let Some(ws_str) = ws.as_str() {
                    if let Some(path) = find_provider_ir(&PathBuf::from(ws_str), prefer_codex) {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

fn find_provider_ir(start: &std::path::Path, prefer_codex: bool) -> Option<PathBuf> {
    let integration_dir = if prefer_codex { ".codex" } else { ".agents" };
    let mut curr = Some(start);
    while let Some(dir) = curr {
        let candidate = dir.join(integration_dir).join("arc_ir.json");
        if candidate.exists() {
            return Some(candidate);
        }
        curr = dir.parent();
    }
    None
}

fn resolve_provider_selection(
    targets: &[ProviderSelectionArg],
    available: &[ProviderTarget],
    argument_name: &str,
) -> Result<Vec<ProviderTarget>> {
    if targets.is_empty() {
        return Ok(available.to_vec());
    }

    let has_all = targets.contains(&ProviderSelectionArg::All);
    if has_all {
        if targets.len() > 1 {
            bail!("'{argument_name} all' cannot be combined with specific provider targets");
        }
        return Ok(available.to_vec());
    }

    let mut selected = Vec::new();
    for target in targets.iter().filter_map(|target| target.provider()) {
        if !available.contains(&target) {
            bail!("Provider target '{target}' is not registered in this Arc build");
        }
        if !selected.contains(&target) {
            selected.push(target);
        }
    }

    if selected.is_empty() {
        bail!("At least one provider target must be selected");
    }

    Ok(selected)
}

fn resolve_os_selection(oses: &[OperatingSystemArg]) -> Result<Vec<String>> {
    let has_all = oses.contains(&OperatingSystemArg::All);
    if has_all {
        if oses.len() > 1 {
            bail!("'--os all' cannot be combined with specific OS targets");
        }
        return Ok(vec![
            "windows".to_string(),
            "linux".to_string(),
            "macos".to_string(),
        ]);
    }

    let mut result = Vec::new();
    for item in oses {
        let os = match item {
            OperatingSystemArg::Windows => "windows".to_string(),
            OperatingSystemArg::Linux => "linux".to_string(),
            OperatingSystemArg::Macos => "macos".to_string(),
            OperatingSystemArg::Host => OsTarget::host()?.as_str().to_string(),
            OperatingSystemArg::All => unreachable!("all was handled above"),
        };
        if !result.contains(&os) {
            result.push(os);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::error::ErrorKind;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct TestDecisionPresenter {
        response: Mutex<VecDeque<arc::DialogResponse>>,
    }

    impl TestDecisionPresenter {
        fn new(response: arc::DialogResponse) -> Self {
            Self {
                response: Mutex::new(VecDeque::from([response])),
            }
        }
    }

    impl arc::DecisionPresenter for TestDecisionPresenter {
        fn present(
            &self,
            request: &arc::DialogRequest,
            _timeout: Duration,
        ) -> anyhow::Result<arc::DialogResponse> {
            let mut response = self
                .response
                .lock()
                .expect("test presenter lock")
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("test presenter response exhausted"))?;
            response.request_id = request.request_id.clone();
            response.bundle_fingerprint = request.bundle_fingerprint.clone();
            Ok(response)
        }
    }

    #[test]
    fn version_flag_reports_the_cargo_package_version() {
        let error = match Cli::try_parse_from(["arc", "--version"]) {
            Ok(_) => panic!("--version should terminate parsing with DisplayVersion"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert_eq!(
            error.to_string(),
            format!("arc {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn lowercase_version_flag_reports_the_cargo_package_version() {
        let error = Cli::try_parse_from(["arc", "-v"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert_eq!(
            error.to_string(),
            format!("arc {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn build_defaults_to_all_providers_and_operating_systems() {
        let cli = Cli::try_parse_from(["arc", "build"]).unwrap();
        let Commands::Build { target, os, .. } = cli.command else {
            panic!("expected build command");
        };

        assert_eq!(target, vec![ProviderSelectionArg::All]);
        assert_eq!(os, vec![OperatingSystemArg::All]);
    }

    #[test]
    fn all_provider_selection_comes_from_the_emitter_registry() {
        let registry = EmitterRegistry::new();
        let registered = registry.providers();

        assert_eq!(
            resolve_provider_selection(&[ProviderSelectionArg::All], &registered, "--target")
                .unwrap(),
            registered
        );
    }

    #[test]
    fn output_short_flag_is_reserved_for_output_directory() {
        let cli = Cli::try_parse_from(["arc", "build", "-o", "dist"]).unwrap();
        let Commands::Build { os, output_dir, .. } = cli.command else {
            panic!("expected build command");
        };

        assert_eq!(os, vec![OperatingSystemArg::All]);
        assert_eq!(output_dir, Some(PathBuf::from("dist")));
    }

    #[test]
    fn decision_json_preserves_request_correlation() {
        let response = arc::DialogResponse {
            schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "request-1".into(),
            bundle_fingerprint: "bundle-1".into(),
            decision: arc::decision_ui::PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: None,
        };

        let encoded = decision_response_json(&response);
        assert_eq!(encoded["schema"], "arc.decision.dialog.response.v2");
        assert_eq!(encoded["request_id"], "request-1");
        assert_eq!(encoded["bundle_fingerprint"], "bundle-1");
        assert_eq!(encoded["decision"]["status"], "allow");
    }

    #[test]
    fn exact_authorization_outcome_builds_exact_ui_request() {
        let operation = arc::CurrentOperation {
            event_type: arc::ArcEventType::ToolCall,
            tool: Some("Bash".into()),
            input: Some(serde_json::json!({"command": "git status"})),
            command_text: Some("git status".into()),
        };
        let ir = arc::BehaviorIR {
            schema: "1.0".into(),
            compiler_version: env!("CARGO_PKG_VERSION").into(),
            build_id: None,
            content_hash: None,
            runtime: Default::default(),
            context: arc::WorkspaceContext {
                workdir: ".".into(),
                instructions_path: None,
                instructions_content: None,
                roles: std::collections::BTreeMap::new(),
            },
            skills: Vec::new(),
            lifecycle_guards: Vec::new(),
            tool_guards: vec![arc::BoundToolGuard {
                id: "guard-auth".into(),
                matcher: arc::BoundMatcher {
                    exact_patterns: vec!["git status".into()],
                    regex_patterns: Vec::new(),
                },
                require: arc::BoundRuleExpression::Decide {
                    prompt: "audit this exact operation".into(),
                },
                on_failure: arc::OnFailureConfig {
                    action: arc::ActionType::Ask,
                    feedback: None,
                },
                order: 1,
                declaration_order: 0,
            }],
            rules: std::collections::BTreeMap::new(),
        };
        let provider = std::sync::Arc::new(
            arc::MockDecisionProvider::new().with_decision("audit this exact operation", true),
        );
        let mut session =
            arc::ArcRuntimeSession::new("session-auth", ir).with_decision_provider(provider);
        let event = arc::ArcEvent::tool_call("session-auth", "event-auth", 1, "Bash", "git status");
        let eval_result = session
            .evaluate_event_aggregate(
                event,
                arc::DecisionExecutionProfile::default(),
                std::path::Path::new("."),
                i64::MAX,
            )
            .expect("aggregate evaluation should succeed");

        assert_eq!(
            eval_result.effective_disposition,
            arc::EffectiveDisposition::Continue
        );
        assert_eq!(eval_result.authorization_requirements.len(), 1);

        // Exact authorization is a separate user decision even when semantic
        // evaluation itself has the Continue disposition.
        let request = interactive_decision_request_from_evaluation_result(
            &eval_result,
            arc::ProviderTarget::Codex,
            arc::ArcEventType::ToolCall,
            "event-auth",
            "invocation-auth",
            Some(operation.clone()),
            Some("Bash git status".into()),
            "this exact tool call once",
        )
        .expect("exact authorization helper should succeed");
        let request = request.expect("exact authorization should open Ask");

        let dialog = request.to_dialog_request("Arc policy decision");
        assert_eq!(
            dialog.presentation_kind,
            arc::PresentationKind::ExactOperationAuthorization
        );
        assert!(dialog.violations.is_empty());
        assert_eq!(dialog.authorizations.len(), 1);
        assert_eq!(dialog.operation.as_deref(), Some("Bash git status"));
    }

    #[test]
    fn local_decision_to_provider_output_records_the_required_event_order() {
        let root = std::env::temp_dir().join(format!(
            "arc_u4_decision_output_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create temporary U4 journal directory");
        let database = root.join("observability.sqlite3");
        let journal = Some(
            arc::ObservabilityJournal::open(&database)
                .expect("open temporary U4 observability journal"),
        );
        let observed = HookObservationContext {
            provider: "codex".into(),
            workspace_id: Some("workspace-u4".into()),
            session_id: "session-u4".into(),
            turn_id: Some("turn-u4".into()),
            invocation_id: "invocation-u4".into(),
        };
        let context = HookDecisionContext {
            decision_ui: DecisionUiArg::Native,
            decision_timeout: Duration::from_secs(10),
            journal: &journal,
            observed: &observed,
            presentation_registry: std::sync::Arc::new(arc::DecisionPresentationRegistry::new()),
        };
        let presenter = std::sync::Arc::new(TestDecisionPresenter::new(arc::DialogResponse {
            schema: arc::DIALOG_RESPONSE_SCHEMA.into(),
            request_id: "presentation-u4".into(),
            bundle_fingerprint: "decision-u4".into(),
            decision: arc::decision_ui::PortableDecision::Allow,
            transport: "arc_embedded_ui".into(),
            theme: "dark".into(),
            message: Some("Approved for this exact operation".into()),
        }));
        let orchestrator = arc::InteractiveDecisionOrchestrator::with_presenter(
            OsTarget::host().expect("supported host"),
            arc::DecisionUiMode::Native,
            Duration::from_secs(10),
            presenter,
        );
        let ir = arc::BehaviorIR {
            schema: "1.0".into(),
            compiler_version: env!("CARGO_PKG_VERSION").into(),
            build_id: None,
            content_hash: None,
            runtime: Default::default(),
            context: arc::WorkspaceContext {
                workdir: ".".into(),
                instructions_path: None,
                instructions_content: None,
                roles: std::collections::BTreeMap::new(),
            },
            skills: Vec::new(),
            lifecycle_guards: Vec::new(),
            tool_guards: vec![arc::BoundToolGuard {
                id: "guard-u4".into(),
                matcher: arc::BoundMatcher {
                    exact_patterns: vec!["git status".into()],
                    regex_patterns: Vec::new(),
                },
                require: arc::BoundRuleExpression::Probe {
                    command: "check_authorized".into(),
                    expected_in: vec!["authorized".into()],
                },
                on_failure: arc::OnFailureConfig {
                    action: arc::ActionType::Ask,
                    feedback: Some("Configured feedback".into()),
                },
                order: 1,
                declaration_order: 0,
            }],
            rules: std::collections::BTreeMap::new(),
        };
        let probe_runner = std::sync::Arc::new(
            arc::MockProbeRunner::new().with_output("check_authorized", "not authorized"),
        );
        let mut session =
            arc::ArcRuntimeSession::new("session-u4", ir).with_probe_runner(probe_runner);
        let input = arc::CodexPreToolUseInput {
            hook_event_name: Some("PreToolUse".into()),
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "git status"}),
            session_id: Some("session-u4".into()),
            turn_id: Some("turn-u4".into()),
            tool_use_id: Some("tool-u4".into()),
            cwd: None,
            model: None,
            transcript_path: None,
        };
        let event = arc::CodexAdapter::pre_tool_use_to_event(&input, 1);
        let eval_result = session
            .evaluate_event_aggregate(
                event.clone(),
                arc::DecisionExecutionProfile::default(),
                std::path::Path::new("."),
                i64::MAX,
            )
            .expect("tool guard evaluation should succeed");
        let request = interactive_decision_request_from_evaluation_result(
            &eval_result,
            ProviderTarget::Codex,
            arc::ArcEventType::ToolCall,
            &event.event_id,
            "invocation-u4",
            None,
            Some("Bash git status".into()),
            "exact operation once",
        )
        .expect("ask outcome should become an interactive request")
        .expect("tool guard should request a decision");

        let dispatch =
            dispatch_interactive_decision_with_orchestrator(request, &orchestrator, &context)
                .expect("interactive decision should resolve");
        let resolution = dispatch.resolution().expect("decision must be received");
        let output = CodexAdapter::embedded_decision_to_pre_tool_use_output(
            dispatch.capability(),
            resolution.portable_decision(),
            resolution.user_message().unwrap_or_default().to_string(),
            "Denied by Arc".into(),
        )
        .expect("Codex output should consume the neutral resolution");
        write_hook_output(&journal, &observed, &output).expect("provider output should be written");

        let events = journal
            .as_ref()
            .unwrap()
            .query(&arc::EventQuery {
                session_id: Some("session-u4".into()),
                ..Default::default()
            })
            .expect("read U4 event chain");
        let event_types: Vec<_> = events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect();
        assert_eq!(
            event_types,
            [
                "DecisionPresentationRequested",
                "DecisionPresentationCompleted",
                "DecisionTransportResolved",
                "DecisionReceived",
                "ProviderOutput"
            ]
        );
        let decision_received = events
            .iter()
            .find(|event| event.event_type == "DecisionReceived")
            .expect("decision event must be recorded");
        let provider_output = events
            .iter()
            .find(|event| event.event_type == "ProviderOutput")
            .expect("provider output event must be recorded");
        assert_eq!(decision_received.details["user_message_present"], true);
        assert_eq!(provider_output.details["capture"], "metadata");
        drop(journal);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn agy_embedded_ui_reason_preserves_user_message() {
        let reason = agy_embedded_ui_pre_tool_use_reason(
            &arc::decision_ui::PortableDecision::Deny,
            "guard-1",
            Some("Do not continue with this operation"),
        );

        assert!(reason.contains("User message: Do not continue with this operation"));
    }

    #[test]
    fn tool_feedback_preserves_message_guards() {
        let failed_guards = vec![
            arc::FailedGuardFeedback {
                guard_id: "message-guard".into(),
                configured_action: arc::ActionType::Message,
                faulted: false,
                configured_feedback: Some("message feedback".into()),
                causes: Vec::new(),
                evidence_fingerprint: "message-evidence".into(),
            },
            arc::FailedGuardFeedback {
                guard_id: "ask-guard".into(),
                configured_action: arc::ActionType::Ask,
                faulted: false,
                configured_feedback: Some("ask feedback".into()),
                causes: Vec::new(),
                evidence_fingerprint: "ask-evidence".into(),
            },
        ];
        let bundle = arc::FailureBundle {
            schema: arc::FAILURE_BUNDLE_SCHEMA.into(),
            bundle_id: "bundle-channel-test".into(),
            invocation_id: "inv-channel-test".into(),
            event_id: "event-channel-test".into(),
            event_type: arc::ArcEventType::ToolCall,
            effective_disposition: arc::EffectiveDisposition::Ask,
            failed_guards,
            evaluation_faults: Vec::new(),
            completeness: arc::EvaluationCompleteness::Complete,
            input_fingerprint: "input-channel-test".into(),
            bundle_fingerprint: "bundle-fingerprint-channel-test".into(),
        };
        let eval_result = arc::ArcEvaluationResult {
            report: arc::EventEvaluationReport {
                schema: arc::EVENT_EVALUATION_REPORT_SCHEMA.into(),
                invocation_id: "inv-channel-test".into(),
                provider: ProviderTarget::Codex,
                event_id: "event-channel-test".into(),
                event_type: arc::ArcEventType::ToolCall,
                input_fingerprint: "input-channel-test".into(),
                guard_results: Vec::new(),
                effective_disposition: arc::EffectiveDisposition::Ask,
                authorization_requirements: Vec::new(),
                activation_cache_summary: arc::ActivationCacheSummary {
                    logical_occurrences: 0,
                    unique_probe_evaluations: 0,
                    unique_decision_evaluations: 0,
                    coalesced_in_flight: 0,
                    reused_completed: 0,
                    physical_faults: 0,
                },
                report_fingerprint: "report-channel-test".into(),
                started_unix_ms: 0,
                completed_unix_ms: 0,
            },
            effective_disposition: arc::EffectiveDisposition::Ask,
            authorization_requirements: Vec::new(),
            failure_bundle: bundle,
        };
        assert_eq!(
            message_feedback_for_tool_call(&eval_result).as_deref(),
            Some("Arc Message feedback: message feedback")
        );
    }

    #[test]
    fn build_rejects_unimplemented_provider() {
        let error = Cli::try_parse_from(["arc", "build", "--target", "claude"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn capabilities_rejects_unknown_provider_during_parsing() {
        let error =
            Cli::try_parse_from(["arc", "capabilities", "--target", "unknown"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn hook_provider_is_case_insensitive_and_rejects_unknown_values() {
        assert!(
            Cli::try_parse_from([
                "arc",
                "hook",
                "run",
                "--event-type",
                "pre-tool-use",
                "--provider",
                "CoDeX",
            ])
            .is_ok()
        );

        let error = Cli::try_parse_from([
            "arc",
            "hook",
            "run",
            "--event-type",
            "pre-tool-use",
            "--provider",
            "unknown",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn hook_event_and_decision_ui_are_validated_during_parsing() {
        let event_error =
            Cli::try_parse_from(["arc", "hook", "run", "--event-type", "unknown"]).unwrap_err();
        assert_eq!(event_error.kind(), ErrorKind::InvalidValue);

        let ui_error = Cli::try_parse_from([
            "arc",
            "hook",
            "run",
            "--event-type",
            "pre-tool-use",
            "--decision-ui",
            "unknown",
        ])
        .unwrap_err();
        assert_eq!(ui_error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn monitor_values_and_relations_are_validated_during_parsing() {
        for args in [
            vec!["arc", "monitor", "--level", "verbose"],
            vec!["arc", "monitor", "--format", "yaml"],
            vec!["arc", "monitor", "--poll-ms", "49"],
        ] {
            let error = Cli::try_parse_from(args).unwrap_err();
            assert!(matches!(
                error.kind(),
                ErrorKind::InvalidValue | ErrorKind::ValueValidation
            ));
        }

        for args in [
            vec!["arc", "monitor", "--clear", "--follow"],
            vec!["arc", "monitor", "--latest", "--session", "session-1"],
        ] {
            let error = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        let error = Cli::try_parse_from(["arc", "monitor", "--poll-ms", "100"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn provider_ir_lookup_never_crosses_integration_directories() {
        let root =
            std::env::temp_dir().join(format!("arc-provider-ir-selection-{}", std::process::id()));
        let nested = root.join("nested");
        let agents_ir = root.join(".agents").join("arc_ir.json");
        let codex_ir = root.join(".codex").join("arc_ir.json");
        std::fs::create_dir_all(agents_ir.parent().unwrap()).unwrap();
        std::fs::create_dir_all(codex_ir.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(&agents_ir, "agents").unwrap();
        std::fs::write(&codex_ir, "codex").unwrap();

        assert_eq!(find_provider_ir(&nested, true), Some(codex_ir));
        assert_eq!(find_provider_ir(&nested, false), Some(agents_ir));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn codex_end_allow_authorizes_remediation_and_blocks_stop() {
        let resolution = arc::resolve_capability(arc::CapabilityContext::cli(
            ProviderTarget::Codex,
            OsTarget::host().unwrap(),
            arc::CapabilityEvent::End,
            arc::ActionType::Ask,
            arc::DecisionUiMode::Native,
        ));
        let output = CodexAdapter::embedded_decision_to_stop_output(
            &resolution,
            arc::decision_ui::PortableDecision::Allow,
            "clean_completion",
            "inv-1",
            Some("workspace is dirty"),
            Some("Run the focused tests first"),
        )
        .unwrap();

        assert_eq!(output.decision.as_deref(), Some("block"));
        assert!(
            output
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("Continue working now"))
        );
    }

    #[test]
    fn codex_end_deny_finishes_but_unresolved_reenters() {
        let resolution = arc::resolve_capability(arc::CapabilityContext::cli(
            ProviderTarget::Codex,
            OsTarget::host().unwrap(),
            arc::CapabilityEvent::End,
            arc::ActionType::Ask,
            arc::DecisionUiMode::Native,
        ));
        let denied = CodexAdapter::embedded_decision_to_stop_output(
            &resolution,
            arc::decision_ui::PortableDecision::Deny,
            "clean_completion",
            "inv-denied",
            None,
            None,
        )
        .unwrap();
        assert_eq!(denied.decision, None);
        assert_eq!(denied.r#continue, None);
        assert!(denied.system_message.is_some());

        let unresolved = CodexAdapter::embedded_decision_to_stop_output(
            &resolution,
            arc::decision_ui::PortableDecision::Unresolved(
                arc::decision_ui::UnresolvedReason::Closed,
            ),
            "clean_completion",
            "inv-unresolved",
            None,
            None,
        )
        .unwrap();
        assert_eq!(unresolved.decision.as_deref(), Some("block"));
        assert!(unresolved.reason.is_some());
    }

    #[test]
    fn gemini_stop_hook_failure_is_fail_closed() {
        let output = hook_failure_value(HookEventArg::Stop, false, "evaluation failed").unwrap();
        assert_eq!(output["decision"], "stop");
        assert_eq!(output["reason"], "evaluation failed");
    }

    #[test]
    fn hook_failures_are_classified_by_type_through_context() {
        let provider_failure = anyhow::Error::new(arc::DecisionError::ExecutionFailed {
            command: "renamed tool".into(),
            exit_code: Some(1),
            stderr_summary: "timed out BehaviorIR".into(),
            stdout_summary: "opaque".into(),
        })
        .context("Failed parsing misleading Input from stdin");
        assert_eq!(
            hook_failure_reason_code(&provider_failure),
            "decision_provider_execution_failed"
        );
        for (class, expected) in [
            (HookFailureContext::InvalidPayload, "invalid_hook_payload"),
            (HookFailureContext::IrResolution, "ir_resolution_failed"),
            (
                HookFailureContext::DecisionTransport,
                "decision_transport_failed",
            ),
            (
                HookFailureContext::UnsupportedProviderEvent,
                "unsupported_provider_event",
            ),
        ] {
            let error = anyhow::anyhow!("mensaje arbitrario")
                .context(class)
                .context("extra context");
            assert_eq!(hook_failure_reason_code(&error), expected);
        }
        for misleading in [
            "Unsupported hook event",
            "Failed parsing AgyStopInput from stdin",
            "Decision CLI command failed with exit code",
            "could not be parsed as a boolean decision",
            "decision deadline timed out",
            "embedded decision UI host",
            "BehaviorIR IR JSON",
        ] {
            assert_eq!(
                hook_failure_reason_code(&anyhow::anyhow!(misleading)),
                "hook_execution_failed"
            );
        }
        let timeout = anyhow::Error::new(arc::DecisionError::TimedOut {
            command: "tool".into(),
        });
        assert_eq!(
            hook_failure_reason_code(&timeout.context(HookFailureContext::DecisionTransport)),
            "decision_transport_timeout"
        );
        let spawn = anyhow::Error::new(arc::DecisionError::SpawnFailed {
            command: "tool".into(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        });
        assert_eq!(
            hook_failure_reason_code(&spawn),
            "decision_provider_spawn_failed"
        );
        let completion = anyhow::Error::new(arc::decision_ui::CompletionError::DeadlineExpired)
            .context("cualquier detalle");
        assert_eq!(
            hook_failure_reason_code(&completion),
            "decision_transport_timeout"
        );
        let io_timeout = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut))
            .context(HookFailureContext::DecisionTransport);
        assert_eq!(
            hook_failure_reason_code(&io_timeout),
            "decision_transport_timeout"
        );
        let preventive = anyhow::Error::new(arc::PreventiveSecurityFaultError {
            tool_name: "Bash".into(),
            reason: "arbitrario".into(),
            raw: serde_json::Value::Null,
        })
        .context("wrapper");
        assert_eq!(
            hook_failure_reason_code(&preventive),
            "invalid_hook_payload"
        );
        let invalid = anyhow::Error::new(arc::DecisionError::UnparseableResponse {
            command: "tool".into(),
            response: "timed out".into(),
        });
        assert_eq!(
            hook_failure_reason_code(&invalid),
            "decision_provider_output_invalid"
        );
    }

    fn codex_stop_directive_to_output(directive: RuntimeDirective) -> arc::CodexStopOutput {
        match directive.disposition {
            RuntimeDisposition::Proceed => arc::CodexStopOutput::allow(),
            RuntimeDisposition::ContinueForRemediation => arc::CodexStopOutput::continue_loop(
                directive
                    .message
                    .unwrap_or_else(|| "Arc guard requires remediation before finishing.".into()),
            ),
            RuntimeDisposition::RequestDecision
            | RuntimeDisposition::RequestAuthorization
            | RuntimeDisposition::Suspend
            | RuntimeDisposition::Abort => arc::CodexStopOutput::abort(format!(
                "[ARC {}] {}",
                directive.execution_id,
                directive.message.unwrap_or_else(|| {
                    "A deterministic user decision is required before this guard can continue."
                        .into()
                })
            )),
            RuntimeDisposition::Prevent => arc::CodexStopOutput::abort(format!(
                "[ARC {}] {}",
                directive.execution_id,
                directive
                    .message
                    .unwrap_or_else(|| "Guard evaluation failed closed.".into())
            )),
            RuntimeDisposition::ReportOnly => arc::CodexStopOutput::allow(),
        }
    }

    #[test]
    fn codex_stop_runtime_fault_never_exposes_internal_details() {
        let snapshot = arc::EvaluationSnapshot::Fault {
            message: PUBLIC_HOOK_FAILURE_REASON.to_string(),
        };
        let arc::EvaluationSnapshot::Fault { message } = snapshot else {
            panic!("runtime faults must become a provider-safe fault snapshot");
        };
        let directive = RuntimeDirective {
            disposition: RuntimeDisposition::Prevent,
            execution_id: "exec-1".into(),
            message: Some(message),
            attempts: arc::runtime::execution::AttemptSnapshot::default(),
            evidence_fingerprint: None,
            reason_code: arc::ReasonCode::EvaluationFault,
            decision_request: None,
        };
        let payload = serde_json::to_string(&codex_stop_directive_to_output(directive)).unwrap();

        assert!(payload.contains(PUBLIC_HOOK_FAILURE_REASON));
        assert!(!payload.contains("SECRET_IN_MESSAGE"));
        assert!(!payload.contains("SECRET_API_KEY"));
        assert!(!payload.contains("SecretPassword123"));
    }

    #[test]
    fn hook_run_rejects_incompatible_explicit_provider_and_event_during_parsing() {
        for args in [
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "pre-invocation",
                "--provider",
                "codex",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "session-start",
                "--provider",
                "gemini",
            ],
        ] {
            let cli = Cli::try_parse_from(args).expect("individual flags should parse");
            let error = validate_cli_relations(&cli).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }

        for valid_args in [
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "session-start",
                "--provider",
                "codex",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "pre-invocation",
                "--provider",
                "gemini",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "pre-tool-use",
                "--provider",
                "codex",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "pre-tool-use",
                "--provider",
                "gemini",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "stop",
                "--provider",
                "codex",
            ],
            vec![
                "arc",
                "hook",
                "run",
                "--event-type",
                "stop",
                "--provider",
                "gemini",
            ],
        ] {
            let cli = Cli::try_parse_from(valid_args).expect("valid flags should parse");
            assert!(validate_cli_relations(&cli).is_ok());
        }
    }

    #[test]
    fn resolve_hook_target_and_failure_values_preserve_provider_wire_protocol() {
        assert_eq!(
            resolve_hook_target(
                HookEventArg::PreInvocation,
                Some(Path::new(".codex/arc_ir.json")),
                None,
                "{}"
            ),
            ProviderTarget::Codex
        );
        assert_eq!(
            resolve_hook_target(
                HookEventArg::SessionStart,
                Some(Path::new(".agents/arc_ir.json")),
                None,
                "{}"
            ),
            ProviderTarget::Gemini
        );
        assert_eq!(
            resolve_hook_target(
                HookEventArg::PreInvocation,
                None,
                None,
                r#"{"hook_event_name":"SessionStart","session_id":"s1"}"#
            ),
            ProviderTarget::Codex
        );
        assert_eq!(
            resolve_hook_target(
                HookEventArg::SessionStart,
                None,
                None,
                r#"{"conversationId":"conv-1","invocationNum":1}"#
            ),
            ProviderTarget::Gemini
        );

        let codex_mismatch =
            validate_hook_provider_event(ProviderTarget::Codex, HookEventArg::PreInvocation)
                .unwrap_err();
        assert_eq!(
            hook_failure_reason_code(&codex_mismatch),
            "unsupported_provider_event"
        );

        let gemini_mismatch =
            validate_hook_provider_event(ProviderTarget::Gemini, HookEventArg::SessionStart)
                .unwrap_err();
        assert_eq!(
            hook_failure_reason_code(&gemini_mismatch),
            "unsupported_provider_event"
        );

        let codex_pre_inv_fail = hook_failure_value(
            HookEventArg::PreInvocation,
            true,
            PUBLIC_HOOK_FAILURE_REASON,
        )
        .unwrap();
        assert_eq!(codex_pre_inv_fail["continue"], false);
        assert_eq!(codex_pre_inv_fail["stopReason"], PUBLIC_HOOK_FAILURE_REASON);
        assert!(codex_pre_inv_fail.get("injectSteps").is_none());

        let gemini_pre_inv_fail = hook_failure_value(
            HookEventArg::PreInvocation,
            false,
            PUBLIC_HOOK_FAILURE_REASON,
        )
        .unwrap();
        assert_eq!(gemini_pre_inv_fail["decision"], "abort");
        assert_eq!(gemini_pre_inv_fail["reason"], PUBLIC_HOOK_FAILURE_REASON);
        assert!(gemini_pre_inv_fail.get("injectSteps").is_some());
        assert!(gemini_pre_inv_fail.get("inject_steps").is_none());

        let gemini_session_start_fail = hook_failure_value(
            HookEventArg::SessionStart,
            false,
            PUBLIC_HOOK_FAILURE_REASON,
        )
        .unwrap();
        assert_eq!(gemini_session_start_fail["decision"], "deny");
        assert_eq!(
            gemini_session_start_fail["reason"],
            PUBLIC_HOOK_FAILURE_REASON
        );
        assert!(
            gemini_session_start_fail
                .get("hookSpecificOutput")
                .is_none()
        );
    }

    #[test]
    fn resolve_ir_file_rejects_cross_provider_custom_ir_path() {
        let root = std::env::temp_dir().join(format!(
            "arc-cross-provider-ir-path-{}",
            uuid::Uuid::new_v4()
        ));
        let agents_ir = root.join(".agents").join("arc_ir.json");
        let codex_ir = root.join(".codex").join("arc_ir.json");
        std::fs::create_dir_all(agents_ir.parent().unwrap()).unwrap();
        std::fs::create_dir_all(codex_ir.parent().unwrap()).unwrap();
        std::fs::write(&agents_ir, "{}").unwrap();
        std::fs::write(&codex_ir, "{}").unwrap();

        assert_eq!(
            resolve_ir_file(Some(codex_ir.clone()), "{}", true),
            Some(codex_ir.clone())
        );
        assert_eq!(resolve_ir_file(Some(agents_ir.clone()), "{}", true), None);
        assert_eq!(
            resolve_ir_file(Some(agents_ir.clone()), "{}", false),
            Some(agents_ir)
        );
        assert_eq!(resolve_ir_file(Some(codex_ir), "{}", false), None);

        let _ = std::fs::remove_dir_all(root);
    }
}
