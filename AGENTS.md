# Development orchestration workflow

This document defines how the agents work together to deliver a product from a request to accepted increments. It is the shared reference for every role.

Language: the harness itself (prompts, artifacts, headings, verdicts, config keys, script messages) is in English. The conversation with the user happens in the user's language.

## Roles and their function

| Role                  | Function                                                                                                                                             | Who launches it                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| **User**              | Product owner. Approves the DoD and each iteration plan, and accepts or rejects increments. Can read any log or plan.                                | —                                 |
| `orchestrator`        | Scrum master. Keeps the board, selects the work items for each iteration, launches roles, enforces gates, and marks items `done`. Main session.      | user                              |
| `analyst`             | Turns the request into requirements and acceptance criteria (DoD).                                                                                   | orchestrator                      |
| `architect`           | Decides technology and structure when a requirement needs it. Records ADRs.                                                                          | orchestrator                      |
| `planner`             | Plans how one work item will be executed: scope, files it touches, tasks, open questions.                                                            | orchestrator                      |
| `test-designer`       | Writes the test plan (cases per acceptance criterion) and the failing tests.                                                                         | orchestrator, implementation-lead |
| `test-auditor`        | Checks that the test plan covers the acceptance criteria.                                                                                            | orchestrator                      |
| `implementation-lead` | Splits an item into slices, dispatches implementers and reviewers, and escalates only what needs a decision.                                         | orchestrator                      |
| `implementer`         | Writes the production code that makes the tests pass, and reports what it finds.                                                                     | implementation-lead               |
| `code-reviewer`       | Reviews tests and code. Only role that marks an item `verified`, with evidence.                                                                      | implementation-lead               |
| `explorer`            | Reads the project (CI, task runners, scripts, README) to complete the detected test, lint and build commands. Read-only; every proposal cites files. | orchestrator, at intake           |

Roles are employees invoked with a specific objective, and each one returns a summary to whoever launched it. A new invocation starts fresh and gets what it needs from files. A correction to work that a role already did is not a new task: the role is resumed with `SendMessage` and its agent ID, so it keeps its context. Only a new task, such as a new slice or a new item, starts a new agent. If an agent cannot be resumed, for example after a session restart, a new one is launched with its previous report attached. The agent IDs are recorded in the log with `verify.py record`. Intermediate roles are allowed when they help the work, as long as each has a clear objective and invocation limits.

Subagents can launch subagents up to 3 levels deep. Only `orchestrator` and `implementation-lead` have the `Agent` tool. The orchestrator's allowlist is inherited by its subagents, so every role that a subagent must launch has to be in that allowlist.

## Organization

Work items are the requirements in the DoD. Each item has an ID (`REQ-NNN`), a state, dependencies, and the files it touches. The DoD is the product backlog. An iteration is the set of items the orchestrator selects for one round of work. An increment is what the user accepts at the end of an iteration.

The orchestrator does not run a fixed sequence over a goal. It advances each item according to its state, and several items can be in different states at the same time.

## Approval gates (product owner)

The orchestrator never proceeds past a gate without the user's approval. A gate is a short summary with a clear decision.

| Gate | When                                                             | What the user approves                                                       |
| ---- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| G1   | After the analyst drafts the DoD                                 | Requirements, criteria, and the open questions                               |
| G2   | Before each iteration starts                                     | The items selected, what each one will do, the roles involved, and the risks |
| G3   | When an architecture decision changes technology, cost, or scope | The ADR                                                                      |
| G4   | After items reach `verified`                                     | Accept the increment, or reopen items with a reason                          |

The orchestrator presents gates in this shape:

```
Iteration 02 — proposal
Items: REQ-003 (login form), REQ-004 (session timeout), REQ-007 (logout)
What will happen: tests for 3 items, implementation in 2 slices, review of each
Parallel: 3 items, max 5 (config)
Risks: REQ-004 depends on REQ-003; both touch src/session.py
Decision needed: approve, change the selection, or stop
```

After G1 is approved, the orchestrator adds `Approved at G1 by the product owner, <date>` under `## Original request` in `dod.md`, and records `gate_g1` in the log. G2 is recorded the same way in the log, with the iteration file as the reference.

If the user is an advanced user, they can open the plan and the logs of any stage. The summary is the default; the files are the detail.

## Levels of detail

Each role writes its handback for the level of the role that receives it. The detail stays in files; the handback points to it.

| Level | Reader                                                             | What it needs                                                       | Handback size                                          |
| ----- | ------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------ |
| L0    | User (product owner)                                               | Goals, items, decisions, outcome, links to evidence                 | 5–15 lines                                             |
| L1    | Orchestrator                                                       | Per item: state, verdict, blockers, decisions taken, artifact paths | minified JSON: keys and counts, paths                  |
| L2    | Implementation lead                                                | Per slice: report objects, exact errors, review findings            | minified JSON; exact errors up to `limits.error_lines` |
| L3    | Engineers (analyst, planner, test-designer, implementer, reviewer) | The full task: code, tests, raw outputs (kept in files)             | the header of their artifact                           |

Rules that follow from this:

- A role never forwards content above its recipient's level. An implementer sends the exact error to the implementation lead, not the log. The implementation lead sends the orchestrator the verdict and the decision needed, not the findings.
- The orchestrator never summarizes a file it has not read. It reads only what it needs to decide.
- The summary for the user (L0) is built from L1 handbacks, not from raw files.

## Communication format

Content is written in one of two forms, according to who reads it and whether a script checks it:

- **Minified JSON** (no spaces, no line breaks outside strings, short keys) for what agents pass to each other and what `verify.py` checks: every handback, and the report, review, audit, and command-exploration deliverables (`impl/report-NN.json`, `reviews/review-NN.json`, `test-plan/audit.json`, `workspace/commands-explorer.json`). These are the artifacts that cost the most tokens when read and written, so their form is the one optimized.
- **Markdown** for everything else: `dod.md`, `arch.md`, ADRs, `plan.md`, `cases.md`, `backlog.md`, iteration records, and the summaries for the user. Escalation cards and handoffs also stay Markdown for now, because they are read on resumption and are kept as records.

Every handback has the same envelope: `r` (role), `st` (status), `v` (verdict, when the role has one), `art` (artifact path or `none`), `esc` (escalation IDs or an empty list), and `n` (counts specific to the role). A role adds only the keys its prompt lists. `rep` carries a report or review object, and `rk` (`report` or `review`) says which one, when the implementation lead passes it along.

A handback is one minified JSON object in the final response, with no text outside it.

## Work item flow

Each item follows the states below. The orchestrator invokes the role that owns the next state.

`pending → test_design → tests_audited → in_implementation → in_review → verified → done`

1. **`pending`.** The analyst has written the requirement and its criteria. The architect is invoked only if the item needs a structural decision (G3 if it changes technology, cost, or scope).
2. **`test_design`.** The planner writes the item's plan, including the files it touches. The test-designer writes the test plan (one case per criterion, with its category and expected result) and the failing tests.
3. **`tests_audited`.** The test-auditor checks that every criterion has at least one test. Tests that inspect structure are allowed; the reviewer judges their strength later.
4. **`in_implementation`.** The implementation lead splits the item into slices. Each slice declares its files. The implementer makes the tests pass.
5. **`in_review`.** The code-reviewer reviews tests and code, and reports the mutation result (how many of the planted faults the tests catch).
6. **`verified`.** The reviewer approves with evidence. If git is enabled, the implementation lead opens a pull request.
7. **`done`.** The orchestrator marks the item done after evidence is checked, or after the pull request is merged when git is enabled. It then reports the increment to the user at G4.

Any state can return to an earlier one. The rules for returning are in the verdicts table below.

## Parallelism and dependencies

- The orchestrator selects up to `iteration.max_parallel_items` items per iteration (default 5 in `.claude/harness.json`). Within that limit, it chooses the number that keeps the work cohesive. The limit exists for quality; the number is not fixed.
- An item can start only when the items it depends on are `done`, for the implementation phase. Design can start earlier.
- Two items that declare the same file cannot be in `in_implementation` at the same time. The orchestrator serializes them.
- When git is enabled, each item works on its own branch. Parallel implementers never share a branch.

## Git organization

Git is the standard flow for this work. It is not active in this project until the project is a repository, and `git.enabled` in `.claude/harness.json` controls it.

When enabled:

- **One branch per item:** `req/REQ-NNN-<slug>`, created from the default branch.
- **Conventional commits:** `type(REQ-NNN): summary`, with types `feat`, `test`, `fix`, `refactor`, `docs`, `chore`. Example: `test(REQ-002): add cases for empty input`.
- **Commits** are made by the implementer after each green phase of a slice, and only after `verify.py` checks pass.
- **Pull request** is opened by the implementation lead after an `APPROVED` review. Its description is the review summary at L1, not the full review.
- **Merge** is done by the user (product owner), or by the orchestrator if the user has approved automatic merges.
- No push, merge, or rebase without the user's explicit approval.

When disabled, the same states apply, and the item becomes `done` on an `APPROVED` review with evidence.

## Identifiers

| Prefix  | What it identifies            | Example                  |
| ------- | ----------------------------- | ------------------------ |
| `REQ-`  | Work item (DoD requirement)   | REQ-001                  |
| `AC-`   | Acceptance criterion of a REQ | AC-001.2                 |
| `CP-`   | Test case                     | CP-014                   |
| `ADR-`  | Architecture decision         | ADR-003                  |
| `ESC-`  | Escalation                    | ESC-007                  |
| `ITER-` | Iteration                     | ITER-02                  |
| `H-`    | Handoff                       | H-02-implementation-lead |

## Verdicts and where they go

| Verdict                                       | Received by         | Action                                      |
| --------------------------------------------- | ------------------- | ------------------------------------------- |
| `CHANGES REQUIRED (code)`                     | implementation-lead | Relaunch `implementer` with the review      |
| `INSUFFICIENT TEST CASES` (existing AC)       | implementation-lead | Launch `test-designer`, then `implementer`  |
| `INSUFFICIENT TEST CASES` (new or changed AC) | orchestrator        | Ask the user at G1 or G2                    |
| `CHANGES REQUIRED (design)`                   | orchestrator        | Launch `planner` or `architect`             |
| `REJECTED` (test audit)                       | orchestrator        | Launch `test-designer` with the corrections |

Each item has at most `max_cycles` correction cycles per phase. When they run out, the item is escalated.

## Who writes which file

The platform refuses `Write` calls from subagents to report and review files (for example `impl/report-NN.json` and `reviews/review-NN.json`). That refusal is not in the harness configuration, so the harness works around it instead of relying on subagents to write those files:

- Each role writes the files it owns in `.claude/harness.json` `permissions`, except report files.
- The implementer returns its report object in the `rep` field of its handback, as minified JSON. The code reviewer does the same with its review object. When a correction is needed, the implementation lead resumes the same agent rather than launching a new one. The implementation lead passes `rep` to the orchestrator in an `AWAITING_REPORT` handback, with `rk` set to `report` or `review`.
- The orchestrator is the main session, not a subagent, so it is not refused. It saves `rep` verbatim to `impl/report-NN.json` or `reviews/review-NN.json` with `Write`, runs `verify.py deliverable report` or `verify.py deliverable review`, and relaunches the implementation lead with that path.
- Bash is checked by `.claude/hooks/guard_bash.py`. Roles that do not run tests (`analyst`, `planner`, `architect`, `explorer`) have no Bash tool. Roles that do run Bash may only execute their allowed `verify.py` subcommands, configured `commands.*`, and read-only git inspection commands; shell redirections obey the same path rules as `Write`.

## Escalation

Escalations are cards in `escalations/ESC-NNN.md`, never raw output.

- **implementer → implementation-lead:** report and exact error (L2).
- **implementation-lead → orchestrator:** only for a design decision, a change to an AC or the DoD, an environment blocker, or an exhausted cycle budget (L1).
- **orchestrator → user:** scope decisions, G1–G3, blocking ambiguities, and environment blockers (L0).

## Deterministic verification

Three mechanisms reduce what depends on an agent's judgment:

1. **Deliverable verification by whoever launched the role.** After each handback, the caller runs `python .claude/scripts/verify.py deliverable <type> <path>`. For Markdown it checks required sections, allowed verdict or state values, and the line budget. For the JSON deliverables (`report`, `review`, `audit`) it checks that the object is minified, that it has its keys and no others, that enumerated values are allowed, that list keys are lists, and the character budget.
2. **Write and Bash permissions per role.** The `PreToolUse` hooks in `.claude/hooks/guard_paths.py` and `.claude/hooks/guard_bash.py` block writes outside each role's paths and restrict Bash commands, based on `agent_type`. The main session has no `agent_type` and is not affected, unless it starts with `--agent`.
   - **Self-edit switch:** to change the harness itself, start the session with `HARNESS_SELF_EDIT=1`. Named roles may then write under `.claude/`, except `settings.json`, `settings.local.json`, and `hooks/`, which stay locked. Writes outside the project remain blocked. Each allowed write is logged as `self_edit_allowed`. The switch is off unless set at startup, and it is meant for changing the harness, not for product work.
3. **Updates by script and DoD validation.** The log, the active iteration, and requirement states change through `verify.py record`, `verify.py state`, and `verify.py dod-set`. Each command changes only its own line or field. Every role records its own transitions with `python .claude/scripts/verify.py record <role> <action> <ref>`, and the orchestrator records each `dod-set` and `state` change right after it. Before marking `done`, the orchestrator runs `python .claude/scripts/verify.py dod <harness>/project/dod.md`.

`SubagentStop` is not used as a gate: in tests, the block did not force the subagent to continue.

## Quality across the process

Quality is checked at every stage, not only at the end:

- **Plan:** the test-auditor checks trace coverage.
- **Tests:** the reviewer reads the tests and checks test strength (including mutation checks when applicable). Structure-only tests are allowed, but the reviewer reports them as weak.
- **Code:** the reviewer checks the implementation against the criteria and the tests.

## Request roots

Each request has its own root, named `.harness-<slug>/`. In this document `<harness>` means the root of the active request: the `harness` key of `.claude/harness.json`.

- The orchestrator creates the root at intake with `python .claude/scripts/verify.py request <slug>`. That command creates the folders, sets the active root, and writes `state.json`. A root is never reused for another request.
- `original-request.md` lives in the root of its request, so each request keeps its own immutable original.
- Finished roots stay in the project, read-only. Nothing else changes them.
- The active root is one value for the whole project. Two requests cannot run at the same time in the same project. To run them in parallel, use separate projects.

## Files

```
<harness>/
├── project/
│   ├── original-request.md      # immutable: the request as the user made it
│   ├── dod.md                   # product backlog: requirements and their state
│   ├── arch.md                  # living architecture, guidance for each item
│   ├── decisions/               # ADR-NNN-<slug>.md
│   └── iterations/              # ITER-NN.md: the approved plan of each iteration
├── log/
│   └── events.ndjson            # append-only, written only through verify.py record
├── items/
│   ├── REQ-NNN-<slug>/          # one folder per work item
│   │   ├── item.md             # scope of the work item: REQs, level, iteration
│   │   ├── plan.md
│   │   ├── backlog.md           # slices, their order, and the files each one declares
│   │   ├── test-plan/           # cases.md and audit.json
│   │   ├── impl/                # report-NN.json and outputs/
│   │   ├── reviews/             # review-NN.json
│   │   ├── escalations/         # ESC-NNN.md
│   │   └── handoffs/            # H-NN-<role>.md, numbered, never deleted
├── state.json                   # active iteration, items in progress, and last event
└── workspace/                   # temporary area
```

Product code does not live inside `<harness>/`. Tests are written in the project, next to the code they test.

## Configuration and portability

Everything project-specific lives in `.claude/harness.json`:

- `harness`: state root, `.harness` by default.
- `max_cycles`: correction cycles per phase.
- `iteration`: `max_parallel_items` (default 5) and `require_user_approval`.
- `git`: whether the project is a repository, branch prefix, commit format, and whether a pull request opens on an approved review.
- `limits`: maximum lines for an exact error.
- `commands`: test, lint, and build commands used by the implementer and the code-reviewer. An empty value means the project has no such step. They are not written by hand. At intake they come from two layers: `verify.py detect` reads the manifests (Cargo.toml, package.json, pyproject.toml, go.mod, pom.xml, Gradle), and the `explorer` reads CI, task runners and the README. `verify.py merge` combines them, keeps the detected command where the two disagree and lists the conflict, and drops any item whose evidence files do not exist. The user decides the conflicts and approves the result at G1. `verify.py commands` then writes `commands` and the `tests` patterns. Multiple stacks are joined with `&&`. The `allow` entries go into `.claude/settings.json` only by the user.
- `tests`: file patterns for test files.
- `permissions`: what each role may write. Accepts `{harness}` and `{tests}`.
- `deliverables`: for each artifact, its format (Markdown by default, or `json`), required sections or keys, allowed values, and budgets (`max_lines` for Markdown, `max_chars` for JSON).
- `dod_states`, `states_with_evidence`, `done_evidence_contains`: verifier rules.

Agents have no fixed paths or commands: they read this configuration. The model and effort of each agent are set only in the frontmatter of its `.md`.

To use the harness in another project:

1. Copy `.claude/agents/`, `.claude/hooks/`, `.claude/scripts/`, `.claude/harness.json`, and `.claude/settings.json`.
2. Adjust `harness.json`: `tests`, `commands`, `git`, and, if the root changes, `harness`.
3. Create `<harness>/` when the first iteration starts.

Without `.claude/harness.json`, the guard restricts nothing and the verifier fails. Agents are loaded at session startup: run the harness in a new session after copying it.

## Pending

- **Default startup as main agent:** `claude --agent orchestrator` works and applies the guard with `agent_type: orchestrator`. It still needs to be set as the default in `settings.json` with the `agent` key, which I have not confirmed.
