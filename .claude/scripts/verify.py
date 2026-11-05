"""Deterministic helpers for the harness: checks, log, state, and DoD updates.

Usage:
  python .claude/scripts/verify.py deliverable <type> <path>
  python .claude/scripts/verify.py dod <path-to-dod.md>
  python .claude/scripts/verify.py record <actor> <action> <ref>
  python .claude/scripts/verify.py state <key> <value>
  python .claude/scripts/verify.py dod-set <REQ-ID> <state> [evidence]
  python .claude/scripts/verify.py request <slug>
  python .claude/scripts/verify.py detect [out.json]
  python .claude/scripts/verify.py merge <detected.json> <explorer.json> <out.json>
  python .claude/scripts/verify.py commands <approved.json>

The request command creates the root .harness-<slug>/ and makes it the active root
in .claude/harness.json. Each request has its own root, and a root is never reused.

Rules (sections, verdicts, budgets, DoD states) come from .claude/harness.json.
Report, review, and audit deliverables are minified JSON: checked by keys, allowed
values, list types, and size. Other deliverables are Markdown: checked by sections.
Checks exit 0 when they pass and 1 when they fail, printing every reason.
Log, state, and DoD updates change only the line or field they touch; nothing is
rewritten as a whole, so the model never has to reproduce a file to update one value.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
CONFIG = os.path.join(ROOT, ".claude", "harness.json")


def load_config():
    with open(CONFIG, encoding="utf-8") as f:
        return json.load(f)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write_atomic(path, text):
    """Write text with LF endings, so Windows does not convert them to CRLF."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def minified(data):
    """Serialize as minified JSON: no spaces, keys in their original order."""
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def value_under_heading(text, heading):
    """Return the first non-empty line under a heading, or None."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == heading:
            for following in lines[i + 1 :]:
                if following.strip():
                    return following.strip()
            return None
    return None


def check_json_deliverable(rule, text):
    """Check a minified JSON deliverable: exact form, keys, allowed values, list types, size."""
    errors = []
    if len(text) > rule["max_chars"]:
        errors.append(f"too long: {len(text)} characters, limit is {rule['max_chars']}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return errors + [f"not valid JSON: {e.msg} (line {e.lineno})"]
    if not isinstance(data, dict):
        return errors + ["top level must be a JSON object"]
    if text.strip() != minified(data):
        errors.append("not minified: remove spaces and line breaks outside strings")

    allowed = set(rule["keys"]) | set(rule.get("optional", []))
    for key in rule["keys"]:
        if key not in data:
            errors.append(f"missing key '{key}'")
    for key in data:
        if key not in allowed:
            errors.append(f"unknown key '{key}'")
    for key, values in rule.get("enums", {}).items():
        if key in data and data[key] not in values:
            errors.append(f"'{key}' is not allowed: {minified(data[key])}")
    for key in rule.get("lists", []):
        if key in data and not isinstance(data[key], list):
            errors.append(f"'{key}' must be a list")
    return errors


def check_deliverable(cfg, kind, path):
    deliverables = cfg["deliverables"]
    if kind not in deliverables:
        return [f"unknown deliverable type: {kind}"]
    if not os.path.isfile(path):
        return [f"file does not exist: {path}"]

    text = read(path)
    rule = deliverables[kind]
    if rule.get("format") == "json":
        return check_json_deliverable(rule, text)

    errors = []

    for section in rule.get("sections", []):
        if not re.search(r"^" + re.escape(section) + r"\s*$", text, re.M):
            errors.append(f"missing section '{section}'")

    if "value_of" in rule:
        heading = rule["value_of"]["heading"]
        allowed = rule["value_of"]["values"]
        value = value_under_heading(text, heading)
        if value is None:
            errors.append(f"'{heading}' has no value")
        elif not any(value.startswith(v) for v in allowed):
            errors.append(f"value under '{heading}' is not allowed: '{value}'")

    if "max_lines" in rule:
        lines = len(text.splitlines())
        if lines > rule["max_lines"]:
            errors.append(f"too long: {lines} lines, limit is {rule['max_lines']}")

    return errors


def dod_rows(text):
    """Return the requirement table rows (ID REQ-NNN) as lists of cells."""
    rows = []
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and re.fullmatch(r"REQ-\d{3}", cells[0]):
            rows.append(cells)
    return rows


def path_exists(path):
    return os.path.exists(os.path.join(ROOT, path.strip()))


def check_review_evidence(req, path):
    """Ensure a review evidence file is valid JSON, APPROVED, and covers req."""
    full = os.path.join(ROOT, path.strip())
    if not full.endswith(".json"):
        return []
    try:
        data = json.loads(read(full))
    except Exception as e:
        return [f"{req}: evidence '{path.strip()}' is not valid JSON ({e})"]
    if not isinstance(data, dict):
        return [f"{req}: evidence '{path.strip()}' must be a JSON object"]
    errors = []
    if data.get("v") != "APPROVED":
        errors.append(f"{req}: review evidence '{path.strip()}' has verdict '{data.get('v')}', expected 'APPROVED'")
    vr = data.get("vr")
    if isinstance(vr, list) and req not in vr:
        errors.append(f"{req}: review evidence '{path.strip()}' does not list {req} in 'vr'")
    return errors


def check_dod_text(cfg, text):
    rows = dod_rows(text)
    if not rows:
        return ["no requirement rows in REQ-NNN format"]

    states = cfg["dod_states"]
    with_evidence = cfg["states_with_evidence"]
    done_marker = cfg.get("done_evidence_contains", "")

    errors = []
    for cells in rows:
        if len(cells) < 7:
            errors.append(f"{cells[0]}: row has fewer than 7 columns")
            continue
        req, state, evidence = cells[0], cells[5], cells[6]

        if state not in states:
            errors.append(f"{req}: invalid state '{state}'")
            continue

        if state in with_evidence:
            paths = [p for p in re.split(r"[,;]", evidence) if p.strip() and p.strip() != "—"]
            if not paths:
                errors.append(f"{req}: state '{state}' without evidence")
                continue
            for p in paths:
                if not path_exists(p):
                    errors.append(f"{req}: evidence '{p.strip()}' does not exist")
                elif not done_marker or done_marker in p:
                    errors.extend(check_review_evidence(req, p))

        if state == "done" and done_marker:
            if not any(done_marker in p for p in re.split(r"[,;]", evidence)):
                errors.append(f"{req}: 'done' requires evidence containing '{done_marker}'")

    return errors


def check_dod(cfg, path):
    if not os.path.isfile(path):
        return [f"file does not exist: {path}"]
    return check_dod_text(cfg, read(path))


def cmd_record(cfg, actor, action, ref):
    line = minified(
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "action": action,
            "ref": ref,
        }
    )
    path = os.path.join(ROOT, cfg["harness"], "log", "events.ndjson")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
    return [], "recorded"


def cmd_state(cfg, key, value):
    path = os.path.join(ROOT, cfg["harness"], "state.json")
    data = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    list_keys = {"items", "active_items"}
    data[key] = [v.strip() for v in value.split(",") if v.strip()] if key in list_keys and "," in value else value
    write_atomic(path, minified(data) + "\n")
    return [], f"state.{key} updated"


def cmd_dod_set(cfg, req, state, evidence=""):
    path = os.path.join(ROOT, cfg["harness"], "project", "dod.md")
    if not os.path.isfile(path):
        return [f"file does not exist: {path}"], ""
    if state not in cfg["dod_states"]:
        return [f"invalid state '{state}'"], ""
    if state in cfg["states_with_evidence"] and not evidence:
        return [f"state '{state}' requires evidence"], ""

    text = read(path)
    lines = text.splitlines()
    index = None
    for i, line in enumerate(lines):
        if line.strip().startswith("|") and re.match(r"^\|\s*" + re.escape(req) + r"\s*\|", line.strip()):
            index = i
            break
    if index is None:
        return [f"requirement {req} not found in dod.md"], ""

    cells = [c.strip() for c in lines[index].strip().strip("|").split("|")]
    if len(cells) < 7:
        return [f"{req}: row has fewer than 7 columns"], ""
    old_state = cells[5]
    states = cfg["dod_states"]
    if old_state in states:
        old_idx, new_idx = states.index(old_state), states.index(state)
        # Allow moving backward (reopen), advancing by 1 step, or tests_audited -> verified
        # (since implementation-lead runs in_implementation and in_review internally).
        if new_idx > old_idx + 1 and not (old_state == "tests_audited" and state == "verified"):
            return [f"{req}: cannot jump from '{old_state}' to '{state}'"], ""
    cells[5] = state
    if evidence:
        cells[6] = evidence
    lines[index] = "| " + " | ".join(cells) + " |"
    new_text = "\n".join(lines) + "\n"

    errors = check_dod_text(cfg, new_text)
    if errors:
        return errors, ""
    write_atomic(path, new_text)
    return [], f"{req} set to {state}"


def report(errors, name, ok_message):
    if errors:
        print(f"FAIL: {name}")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: {name}" + (f" ({ok_message})" if ok_message else ""))
    return 0


def cmd_request(cfg, slug):
    """Create the root of one request and make it the active root in harness.json."""
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", slug):
        return [f"invalid request slug '{slug}': use lowercase words separated by dashes"], ""
    root = f".harness-{slug}"
    absolute = os.path.join(ROOT, root)
    if os.path.exists(absolute):
        return [f"request root already exists: {root}"], ""

    for folder in ("project", "log", "items"):
        os.makedirs(os.path.join(absolute, folder), exist_ok=True)
    write_atomic(os.path.join(absolute, "state.json"), minified({"phase": "intake"}) + "\n")

    # Change only the "harness" value, so the hand-written formatting of the config survives.
    text, count = re.subn(
        r'("harness"\s*:\s*)"[^"]*"',
        lambda m: m.group(1) + json.dumps(root),
        read(CONFIG),
        count=1,
    )
    if count != 1:
        return ['"harness" key not found in harness.json'], ""
    write_atomic(CONFIG, text)
    cfg["harness"] = root
    return [], f"active root is now {root}"


SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", "out", "vendor", ".venv", "venv", "__pycache__", ".svelte-kit", ".next", ".gradle", ".idea"}
WATCHED = {"Cargo.toml", "package.json", "pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"}
PYTEST_CONFIGS = ("pyproject.toml", "pytest.ini", "setup.cfg", "tox.ini")
GRADLE_FILES = ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")
PM_LOCKFILES = (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("bun.lockb", "bun"), ("bun.lock", "bun"))
NODE_PLACEHOLDER = "no test specified"
TEST_GLOBS = {
    "rust": ["**/tests/**"],
    "node": ["**/*.test.ts", "**/*.test.tsx", "**/*.test.js", "**/*.test.jsx", "**/*.spec.ts", "**/*.spec.tsx", "**/*.spec.js", "**/*.spec.jsx", "**/__tests__/**"],
    "python": ["**/test_*", "**/*_test.*", "**/tests/**"],
    "go": ["**/*_test.go"],
    "java": ["**/src/test/**"],
}


def scan(root, max_depth=3):
    """Map each watched file name to the folders that hold it, relative to the root."""
    hits = {}
    base = root.rstrip(os.sep).count(os.sep)
    for current, dirs, files in os.walk(root):
        depth = current.rstrip(os.sep).count(os.sep) - base
        dirs[:] = [] if depth >= max_depth else [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".harness")]
        rel = os.path.relpath(current, root).replace(os.sep, "/")
        for name in files:
            if name in WATCHED:
                hits.setdefault(name, set()).add(rel)
            elif name.startswith("test_") and name.endswith(".py"):
                hits.setdefault("test_*.py", set()).add(rel)
    return hits


def join_dir(d, name):
    return name if d == "." else f"{d}/{name}"


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def node_run(pm, d, script):
    if d == ".":
        return f"{pm} run {script}"
    prefix = {"npm": "npm --prefix", "pnpm": "pnpm -C", "yarn": "yarn --cwd", "bun": "bun --cwd"}[pm]
    return f"{prefix} {d} run {script}"


def rust_stacks(hits):
    stacks = []
    for d in sorted(hits.get("Cargo.toml", ())):
        manifest = join_dir(d, "Cargo.toml")
        stacks.append({
            "stack": "rust",
            "tests": f"cargo test --manifest-path {manifest}",
            "build": f"cargo build --manifest-path {manifest}",
            "lint": f"cargo clippy --manifest-path {manifest}",
            "globs": TEST_GLOBS["rust"],
            "evidence": [manifest],
        })
    return stacks


def node_stacks(root, hits, warnings):
    stacks = []
    for d in sorted(hits.get("package.json", ())):
        manifest = join_dir(d, "package.json")
        try:
            scripts = json.loads(read_text(os.path.join(root, manifest))).get("scripts", {})
        except (json.JSONDecodeError, AttributeError):
            warnings.append(f"{manifest}: not valid JSON, skipped")
            continue
        pm = "npm"
        for lockfile, name in PM_LOCKFILES:
            if any(os.path.isfile(os.path.join(root, x, lockfile)) for x in (d, ".")):
                pm = name
                break
        test = scripts.get("test", "")
        stacks.append({
            "stack": f"node-{pm}",
            "tests": node_run(pm, d, "test") if test and NODE_PLACEHOLDER not in test else "",
            "build": node_run(pm, d, "build") if "build" in scripts else "",
            "lint": node_run(pm, d, "lint") if "lint" in scripts else "",
            "globs": TEST_GLOBS["node"],
            "evidence": [manifest],
        })
    return stacks


def python_stacks(root, hits):
    found = {}
    for name in PYTEST_CONFIGS:
        for d in hits.get(name, ()):
            if "pytest" in read_text(os.path.join(root, join_dir(d, name))):
                found.setdefault(d, []).append(join_dir(d, name))
    if not found and "test_*.py" in hits:
        found["."] = ["test_*.py"]
    stacks = []
    for d in sorted(found):
        command = "python -m pytest" if d == "." else f"python -m pytest {d}"
        stacks.append({
            "stack": "python-pytest",
            "tests": command,
            "build": "",
            "lint": "",
            "globs": TEST_GLOBS["python"],
            "evidence": found[d],
        })
    return stacks


def go_stacks(hits):
    stacks = []
    for d in sorted(hits.get("go.mod", ())):
        prefix = "" if d == "." else f"-C {d} "
        stacks.append({
            "stack": "go",
            "tests": f"go {prefix}test ./...",
            "build": f"go {prefix}build ./...",
            "lint": "",
            "globs": TEST_GLOBS["go"],
            "evidence": [join_dir(d, "go.mod")],
        })
    return stacks


def java_stacks(hits):
    stacks = []
    for d in sorted(hits.get("pom.xml", ())):
        pom = join_dir(d, "pom.xml")
        stacks.append({
            "stack": "java-maven",
            "tests": f"mvn -f {pom} test",
            "build": f"mvn -f {pom} package -DskipTests",
            "lint": "",
            "globs": TEST_GLOBS["java"],
            "evidence": [pom],
        })
    gradle_dirs = set()
    for name in GRADLE_FILES:
        gradle_dirs |= hits.get(name, set())
    for d in sorted(gradle_dirs):
        wrapper = "./gradlew" if d in hits.get("gradlew", ()) else "gradle"
        prefix = "" if d == "." else f"-p {d} "
        stacks.append({
            "stack": "java-gradle",
            "tests": f"{wrapper} {prefix}test",
            "build": f"{wrapper} {prefix}build -x test",
            "lint": "",
            "globs": TEST_GLOBS["java"],
            "evidence": [join_dir(d, "build.gradle*") if d != "." else "build.gradle*"],
        })
    return stacks


def allow_entries(commands):
    """One exact Bash permission per command, so the user can allow only what was approved."""
    entries = []
    for key in ("tests", "lint", "build"):
        for command in commands.get(key, "").split(" && ") if commands.get(key) else []:
            if f"Bash({command})" not in entries:
                entries.append(f"Bash({command})")
    return entries


def detect(root):
    """Propose test, lint and build commands from the project's manifests. Writes nothing."""
    hits = scan(root)
    warnings = []
    stacks = (
        rust_stacks(hits)
        + node_stacks(root, hits, warnings)
        + python_stacks(root, hits)
        + go_stacks(hits)
        + java_stacks(hits)
    )
    if not stacks:
        warnings.append("no known manifest found: set the commands by hand or extend detect")

    commands = {key: " && ".join(s[key] for s in stacks if s[key]) for key in ("tests", "lint", "build")}
    globs = []
    for s in stacks:
        for g in s["globs"]:
            if g not in globs:
                globs.append(g)
    return {
        "stacks": [{k: v for k, v in s.items() if k != "globs"} for s in stacks],
        "commands": commands,
        "tests_globs": globs,
        "allow": allow_entries(commands),
        "warnings": warnings,
    }


INFORMATIONAL_KEYS = {"allow", "sources", "conflicts", "rejected", "notes", "warnings", "stacks"}


def evidence_error(root, evidence):
    """Return a reason when evidence is not a non-empty list of existing project paths, else None."""
    if not isinstance(evidence, list) or not evidence or not all(isinstance(p, str) for p in evidence):
        return "evidence must be a non-empty list of paths"
    missing = [p for p in evidence if not os.path.exists(os.path.join(root, p))]
    return f"evidence does not exist: {', '.join(missing)}" if missing else None


def cmd_merge(root, det_path, exp_path, out_path):
    """Merge the detected commands with the explorer's proposal. Explorer items need evidence files."""
    for path in (det_path, exp_path):
        if not os.path.isfile(path):
            return [f"file does not exist: {path}"], ""
    try:
        detected = json.loads(read(det_path))
        explored = json.loads(read(exp_path))
    except json.JSONDecodeError as e:
        return [f"not valid JSON: {e.msg} (line {e.lineno})"], ""
    if not isinstance(detected, dict) or not isinstance(detected.get("commands"), dict):
        return ["the detected file must come from 'verify.py detect'"], ""

    commands = {key: detected["commands"].get(key, "") for key in ("tests", "lint", "build")}
    sources = {key: "detect" if commands[key] else "none" for key in commands}
    conflicts, rejected = [], []
    for item in explored.get("cmd", []):
        if not isinstance(item, dict):
            rejected.append(f"{minified(item)}: must be an object")
            continue
        key, text, evidence = item.get("k"), item.get("c"), item.get("ev")
        if key not in commands:
            rejected.append(f"{minified(item)}: key must be tests, lint or build")
            continue
        if not isinstance(text, str) or not text or "\n" in text:
            rejected.append(f"{key}: command must be a single-line string")
            continue
        problem = evidence_error(root, evidence)
        if problem:
            rejected.append(f"{key}: {problem}")
            continue
        if text == commands[key]:
            sources[key] = "detect+explorer"
        elif not commands[key]:
            commands[key] = text
            sources[key] = "explorer"
        else:
            conflicts.append({"key": key, "current": commands[key], "proposed": text, "ev": evidence})

    globs = list(detected.get("tests_globs", []))
    for item in explored.get("globs", []):
        if not isinstance(item, dict):
            rejected.append(f"{minified(item)}: must be an object")
            continue
        pattern, evidence = item.get("g"), item.get("ev")
        problem = evidence_error(root, evidence) if isinstance(pattern, str) and pattern else "glob must be a non-empty string"
        if problem:
            rejected.append(f"glob {minified(item)}: {problem}")
            continue
        if pattern not in globs:
            globs.append(pattern)

    merged = {
        "commands": commands,
        "tests_globs": globs,
        "allow": allow_entries(commands),
        "sources": sources,
        "conflicts": conflicts,
        "rejected": rejected,
        "notes": explored.get("notes", []),
        "warnings": detected.get("warnings", []),
    }
    write_atomic(out_path, minified(merged) + "\n")
    return [], f"{len(conflicts)} conflict(s), {len(rejected)} rejected"


def cmd_commands(cfg, path):
    """Write approved commands and test patterns into harness.json, changing only those two keys."""
    if not os.path.isfile(path):
        return [f"file does not exist: {path}"], ""
    try:
        data = json.loads(read(path))
    except json.JSONDecodeError as e:
        return [f"not valid JSON: {e.msg} (line {e.lineno})"], ""

    errors = []
    if not isinstance(data, dict) or set(data) - {"commands", "tests_globs"} - INFORMATIONAL_KEYS:
        return ["top level must contain 'commands' and 'tests_globs', and only informational keys besides"], ""
    if data.get("conflicts"):
        keys = ", ".join(str(c.get("key", "?")) for c in data["conflicts"] if isinstance(c, dict))
        return [f"resolve the conflicts before writing: {keys}"], ""
    commands = data.get("commands")
    globs = data.get("tests_globs")
    if not isinstance(commands, dict) or set(commands) - {"tests", "lint", "build"}:
        errors.append("'commands' must be an object with only tests, lint and build")
    else:
        for key in ("tests", "lint", "build"):
            value = commands.get(key, "")
            if not isinstance(value, str) or "\n" in value:
                errors.append(f"'commands.{key}' must be a single-line string")
        if not commands.get("tests"):
            errors.append("'commands.tests' is required")
    if not isinstance(globs, list) or not globs or not all(isinstance(g, str) for g in globs):
        errors.append("'tests_globs' must be a non-empty list of strings")
    if errors:
        return errors, ""

    values = {key: commands.get(key, "") for key in ("tests", "lint", "build")}
    block = '"commands": {\n' + ",\n".join(
        f"    {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}" for k, v in values.items()
    ) + "\n  }"
    text, n_commands = re.subn(r'"commands"\s*:\s*\{[^{}]*\}', lambda m: block, read(CONFIG), count=1)
    text, n_globs = re.subn(
        r'"tests"\s*:\s*\[[^\[\]]*\]',
        lambda m: '"tests": ' + json.dumps(globs, ensure_ascii=False),
        text,
        count=1,
    )
    if n_commands != 1 or n_globs != 1:
        return ['"commands" or "tests" key not found in harness.json'], ""
    json.loads(text)  # the result must still be valid JSON before anything is written
    write_atomic(CONFIG, text)
    return [], "commands and test patterns written to harness.json"


def main(argv):
    if not os.path.isfile(CONFIG):
        print(f"FAIL: configuration not found: {CONFIG}")
        return 1

    cfg = load_config()
    args = argv[1:]

    if len(args) >= 3 and args[0] == "deliverable":
        return report(check_deliverable(cfg, args[1], args[2]), f"deliverable {args[1]} {args[2]}", "")
    if len(args) >= 2 and args[0] == "dod":
        return report(check_dod(cfg, args[1]), f"dod {args[1]}", "")
    if len(args) >= 4 and args[0] == "record":
        errors, msg = cmd_record(cfg, args[1], args[2], " ".join(args[3:]))
        return report(errors, "record", msg)
    if len(args) >= 3 and args[0] == "state":
        errors, msg = cmd_state(cfg, args[1], " ".join(args[2:]))
        return report(errors, "state", msg)
    if len(args) >= 2 and args[0] == "request":
        errors, msg = cmd_request(cfg, args[1])
        return report(errors, f"request {args[1]}", msg)
    if len(args) >= 3 and args[0] == "dod-set":
        errors, msg = cmd_dod_set(cfg, args[1], args[2], " ".join(args[3:]))
        return report(errors, f"dod-set {args[1]} {args[2]}", msg)

    if args[:1] == ["detect"] and len(args) <= 2:
        result = minified(detect(ROOT))
        if len(args) == 1:
            print(result)
            return 0
        write_atomic(args[1], result + "\n")
        return report([], f"detect {args[1]}", "proposal written")
    if len(args) == 4 and args[0] == "merge":
        errors = check_deliverable(cfg, "explore", args[2])
        msg = ""
        if not errors:
            errors, msg = cmd_merge(ROOT, args[1], args[2], args[3])
        return report(errors, "merge", msg)
    if len(args) >= 2 and args[0] == "commands":
        errors, msg = cmd_commands(cfg, args[1])
        return report(errors, "commands", msg)

    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
