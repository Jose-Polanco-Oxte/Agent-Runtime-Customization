"""PreToolUse hook: restricts where each agent role can write.

Rules live in .claude/harness.json under "permissions". If that file does not
exist, the harness is not installed in the project and the hook restricts nothing.

The hook only acts when the event carries `agent_type` (that is, when a named
agent triggers it). The main session has no `agent_type`, unless it starts with
--agent, in which case its type is the main agent's.

Exits with code 2 to block the write and 0 to allow it.

Fail-closed: once a named role is known (or the event cannot be read), any error
blocks the write. Claude Code only blocks on exit code 2, so an uncaught exception
(exit 1) would let the write through.

Paths are resolved (symlinks, junctions, `..`) before they are compared, and on
Windows the comparison ignores case, because NTFS does.

Self-edit switch: when HARNESS_SELF_EDIT=1 is set at startup, named roles may write
under .claude/ even if their rules deny it. The switch never opens the guard itself
(.claude/hooks/), the settings that load it, or anything outside the project. Each
write it allows is recorded in the active log.

guard_bash.py imports this module, so shell redirections follow the same rules.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
CONFIG = os.path.join(ROOT, ".claude", "harness.json")
SELF_EDIT_ENV = "HARNESS_SELF_EDIT"
SELF_EDIT_LOCKED = [".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/**"]
CASE_INSENSITIVE = os.name == "nt"


def expand(patterns, cfg):
    """Replace {harness} and {tests} placeholders in the configured patterns."""
    harness = cfg.get("harness", ".harness")
    tests = cfg.get("tests", [])
    result = []
    for pattern in patterns:
        if pattern == "{tests}":
            result.extend(tests)
        else:
            result.append(pattern.replace("{harness}", harness))
    return result


def load_config():
    with open(CONFIG, encoding="utf-8") as f:
        return json.load(f)


def load_rules(cfg):
    return {
        role: {
            "allow": expand(rule.get("allow", []), cfg),
            "deny": expand(rule.get("deny", []), cfg),
        }
        for role, rule in cfg.get("permissions", {}).items()
    }


def glob_to_regex(pattern):
    """Convert a simple glob (with ** and *) into a regular expression."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile("^" + out + "$")


def fold(text):
    """Lowercase on Windows, where the file system ignores case."""
    return text.lower() if CASE_INSENSITIVE else text


def matches(path, patterns):
    return any(glob_to_regex(fold(p)).match(fold(path)) for p in patterns)


def relative_to_root(file_path):
    """Return the resolved path relative to the project, with / separators, or None if outside."""
    root = os.path.realpath(ROOT)
    target = os.path.realpath(os.path.join(root, file_path))
    try:
        if os.path.commonpath([fold(root), fold(target)]) != fold(root):
            return None
    except ValueError:  # different drives on Windows
        return None
    return os.path.relpath(target, root).replace("\\", "/")


def self_edit_allows(rel):
    """True when the switch is on and the path is harness configuration, not the guard."""
    if os.environ.get(SELF_EDIT_ENV) != "1":
        return False
    return fold(rel).startswith(".claude/") and not matches(rel, SELF_EDIT_LOCKED)


def log_self_edit(cfg, role, rel):
    """Append the allowed write to the active log, in the format of verify.py record."""
    log_dir = os.path.join(ROOT, cfg.get("harness", ".harness"), "log")
    if not os.path.isdir(log_dir):
        return
    line = json.dumps(
        {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": role,
            "action": "self_edit_allowed",
            "ref": rel,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    with open(os.path.join(log_dir, "events.ndjson"), "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")


def path_verdict(cfg, rules, role, file_path):
    """Return None when the role may write file_path, else the reason it may not.

    Relative paths are resolved against the project root; pass an absolute path to
    resolve against another directory.
    """
    rel = relative_to_root(file_path)
    if rel is None:
        return f"role '{role}' cannot write outside the project ({file_path})"
    rule = rules[role]
    if matches(rel, rule["deny"]) or not matches(rel, rule["allow"]):
        if self_edit_allows(rel):
            log_self_edit(cfg, role, rel)
            return None
        return f"role '{role}' cannot write '{rel}'. Allowed paths: {', '.join(rule['allow']) or 'none'}"
    return None


def block(message):
    print(f"Blocked: {message}", file=sys.stderr)
    return 2


def read_event():
    """Return (event, None) or (None, exit code) when the event cannot be read."""
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("event is not a JSON object")
        return data, None
    except Exception as e:  # cannot tell who is acting: refuse
        return None, block(f"guard could not read the hook event ({e})")


def run(check):
    """Shared entry point: config gate, event parsing, and fail-closed error handling."""
    if not os.path.isfile(CONFIG):
        return 0
    data, code = read_event()
    if data is None:
        return code
    role = data.get("agent_type")
    if not role:
        return 0  # main session: not restricted
    try:
        return check(data, role)
    except Exception as e:  # a named role: never let an error open the guard
        return block(f"guard error for role '{role}' ({type(e).__name__}: {e})")


def check(data, role):
    cfg = load_config()
    rules = load_rules(cfg)
    if role not in rules:
        return 0

    tool_input = data.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    if not file_path:
        return block(f"role '{role}': write event has no file path")

    reason = path_verdict(cfg, rules, role, file_path)
    return block(reason) if reason else 0


def main():
    return run(check)


if __name__ == "__main__":
    sys.exit(main())
