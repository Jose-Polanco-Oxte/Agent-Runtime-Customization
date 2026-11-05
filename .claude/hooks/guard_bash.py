"""PreToolUse hook for Bash: limits which shell commands each agent role can run.

Rules live in .claude/harness.json under "bash". A role listed in "permissions"
but not in "bash.roles" cannot run Bash at all. Roles that are not in
"permissions", and the main session, are not restricted. Without a "bash" key the
hook does not enforce anything, so older configurations keep working.

A command is allowed only when it parses as simple commands joined by `&&`, `||`
and `|`, and every one of them is:

- `python [-B|-u] .claude/scripts/verify.py <subcommand> ...`, with a subcommand the
  role may use;
- one of the project commands (`commands.tests`, `.lint`, `.build`, split on `&&`),
  or a role `extra` prefix, followed by any further arguments;
- a read-only command from `bash.readonly`;
- `cd <dir inside the project>`.

Writes through redirection (`>`, `>>`, `&>`, `2>`) are checked against the role's
write permissions, with guard_paths.py. `/dev/null` is always allowed.

Refused outright: `;`, `&` (background), `$` and backticks (substitution),
subshells, here-documents, line breaks, and environment assignments not listed in
`bash.env_allow`.

This prevents casual writes through the shell (heredocs, `python -c`, `cp`, `sed
-i`). It cannot stop code the approved commands run (a build script, a test), so it
narrows the shell; it does not sandbox it.

Exits with code 2 to block and 0 to allow. Fail-closed like guard_paths.py.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard_paths as gp  # noqa: E402

VERIFY = ".claude/scripts/verify.py"
PYTHONS = {"python", "python3", "py", "python.exe", "python3.exe", "py.exe"}
PYTHON_FLAGS = {"-B", "-u"}
NULL_TARGETS = {"/dev/null", "nul"}
GLOB_CHARS = set("*?[")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Arguments that make read-only commands write (git diff --output=FILE).
WRITE_ARGS = ("--output",)


class Unsafe(Exception):
    """The command uses a shell feature the guard does not allow."""


# ---------------------------------------------------------------- lexer


def lex(command):
    """Split a command into ("w", word), ("op", op), ("redir", target-kind) tokens.

    Quotes are resolved like the shell does. Anything that would make the shell run
    or substitute something the guard cannot see raises Unsafe.
    """
    tokens = []
    word = None  # current word, or None when between words
    quoted = False  # the current word had quotes (so "2">x is not a descriptor)
    i, n = 0, len(command)

    def flush():
        nonlocal word, quoted
        if word is not None:
            tokens.append(("w", word))
        word, quoted = None, False

    while i < n:
        c = command[i]
        if c in " \t":
            flush()
            i += 1
        elif c in "\r\n":
            raise Unsafe("line breaks: run one command line at a time")
        elif c == "'":
            end = command.find("'", i + 1)
            if end < 0:
                raise Unsafe("unterminated single quote")
            word = (word or "") + command[i + 1 : end]
            quoted = True
            i = end + 1
        elif c == '"':
            j, text = i + 1, ""
            while j < n and command[j] != '"':
                ch = command[j]
                if ch in "$`":
                    raise Unsafe("substitution inside double quotes: use single quotes")
                if ch == "\\" and j + 1 < n and command[j + 1] in '"\\':
                    text += command[j + 1]
                    j += 2
                    continue
                text += ch
                j += 1
            if j >= n:
                raise Unsafe("unterminated double quote")
            word = (word or "") + text
            quoted = True
            i = j + 1
        elif c == "\\":
            if i + 1 >= n:
                raise Unsafe("trailing backslash")
            word = (word or "") + command[i + 1]
            i += 2
        elif c in "$`":
            raise Unsafe("variables and command substitution are not allowed")
        elif c in "()":
            raise Unsafe("subshells are not allowed")
        elif c == "#" and word is None:
            raise Unsafe("comments are not allowed")
        elif c in "&|;<>":
            fd = None
            if c in "<>" and word is not None and word.isdigit() and not quoted:
                fd, word = word, None
            flush()
            i = lex_operator(command, i, fd, tokens)
        else:
            word = (word or "") + c
            i += 1
    flush()
    return tokens


def lex_operator(command, i, fd, tokens):
    """Append the operator at command[i] to tokens and return the next index."""
    rest = command[i:]
    if rest.startswith("<<"):
        raise Unsafe("here-documents and here-strings are not allowed")
    for op in ("&&", "||"):
        if rest.startswith(op):
            tokens.append(("op", op))
            return i + 2
    if rest.startswith("|&"):
        tokens.append(("op", "|"))
        return i + 2
    if rest.startswith("&>"):
        tokens.append(("redir", "out"))
        return i + (3 if rest.startswith("&>>") else 2)
    if rest[0] in ";&":
        raise Unsafe("';' and background '&' are not allowed: join commands with &&")
    if rest[0] == "|":
        tokens.append(("op", "|"))
        return i + 1
    if rest.startswith(">&") or rest.startswith("<&"):
        # >&2, 2>&1, <&0, >&- duplicate descriptors; >&file writes like &>file.
        m = re.match(r"[<>]&(\d+|-)(?=$|[\s|&;<>])", rest)
        if m:
            return i + m.end()
        if rest[0] == "<":
            raise Unsafe("unsupported input redirection")
        tokens.append(("redir", "out"))
        return i + 2
    if rest[0] == "<":
        tokens.append(("redir", "in"))
        return i + 1
    # > , >> , >|
    tokens.append(("redir", "out"))
    return i + (2 if rest.startswith(">>") or rest.startswith(">|") else 1)


def parse(command):
    """Return a list of (joiner, pipeline); a pipeline is a list of (words, out_targets)."""
    tokens = lex(command)
    chains, pipeline, words, outs = [], [], [], []
    joiner = None
    i = 0

    def end_command():
        nonlocal words, outs
        if not words:
            raise Unsafe("empty command around an operator")
        pipeline.append((words, outs))
        words, outs = [], []

    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "w":
            words.append(value)
        elif kind == "redir":
            if i + 1 >= len(tokens) or tokens[i + 1][0] != "w":
                raise Unsafe("redirection without a target")
            if value == "out":
                outs.append(tokens[i + 1][1])
            i += 1
        elif value == "|":
            end_command()
        else:  # && or ||
            end_command()
            chains.append((joiner, pipeline))
            pipeline, joiner = [], value
        i += 1
    end_command()
    chains.append((joiner, pipeline))
    return chains


# ---------------------------------------------------------------- policy


def split_words(command):
    """Words of one configured command; it must be a plain simple command."""
    tokens = lex(command)
    if any(kind != "w" for kind, _ in tokens):
        raise Unsafe(f"configured command is not a simple command: {command}")
    return [value for _, value in tokens]


def prefixes(cfg, policy):
    """Allowed command prefixes for a role, as word lists."""
    result = []
    if policy.get("commands"):
        for key in ("tests", "lint", "build"):
            for part in (cfg.get("commands", {}).get(key) or "").split("&&"):
                if part.strip():
                    result.append(split_words(part.strip()))
    for extra in policy.get("extra", []):
        result.append(split_words(extra))
    return result


def to_native(path):
    """Expand ~ and turn a Git Bash path (/c/Users) into a Windows path."""
    path = os.path.expanduser(path)
    if os.name == "nt":
        m = re.match(r"^/([a-zA-Z])(/.*)?$", path)
        if m:
            path = f"{m.group(1)}:{m.group(2) or '/'}"
    return path


def resolve(cwd, path):
    return os.path.join(cwd, to_native(path))


def is_verify(words, cwd):
    """Return the verify.py subcommand when words run verify.py, else None."""
    if not words or gp.fold(words[0]) not in PYTHONS:
        return None
    i = 1
    while i < len(words) and words[i] in PYTHON_FLAGS:
        i += 1
    if i >= len(words):
        return None
    script = os.path.realpath(resolve(cwd, words[i]))
    expected = os.path.realpath(os.path.join(gp.ROOT, VERIFY))
    if gp.fold(script) != gp.fold(expected):
        return None
    return words[i + 1] if i + 1 < len(words) else ""


def starts_with(words, prefix):
    return len(words) >= len(prefix) and words[: len(prefix)] == prefix


def command_reason(words, cwd, cfg, policy, readonly):
    """Return None when the simple command is allowed, else why not."""
    sub = is_verify(words, cwd)
    if sub is not None:
        allowed = policy.get("verify", [])
        if "*" in allowed or sub in allowed:
            return None
        return f"verify.py '{sub}' is not allowed for this role (allowed: {', '.join(allowed) or 'none'})"

    if any(starts_with(words, p) for p in prefixes(cfg, policy)):
        return None

    if any(starts_with(words, p) for p in readonly):
        if any(w.startswith(WRITE_ARGS) for w in words):
            return f"'{' '.join(words[:2])}' with an output option writes files"
        return None

    return f"'{' '.join(words)}' is not an allowed command"


def allowed_summary(cfg, policy, readonly):
    parts = []
    if policy.get("verify"):
        parts.append(f"verify.py {'/'.join(policy['verify'])}")
    parts += [" ".join(p) for p in prefixes(cfg, policy)]
    parts += [" ".join(p) for p in readonly]
    return "; ".join(parts) or "nothing"


def check(data, role):
    cfg = gp.load_config()
    rules = gp.load_rules(cfg)
    bash = cfg.get("bash")
    if role not in rules or bash is None:
        return 0

    policy = bash.get("roles", {}).get(role)
    if policy is None:
        return gp.block(f"role '{role}' cannot run Bash. Use the Read, Grep, Glob and Write tools.")

    command = ((data.get("tool_input") or {}).get("command") or "").strip()
    if not command:
        return gp.block(f"role '{role}': Bash event has no command")

    readonly = [split_words(r) for r in bash.get("readonly", [])]
    env_allow = set(bash.get("env_allow", []))
    cwd = data.get("cwd") or gp.ROOT

    try:
        chains = parse(command)
    except Unsafe as e:
        return gp.block(f"role '{role}': {e}")

    for _, pipeline in chains:
        for words, outs in pipeline:
            for target in outs:
                if gp.fold(target) in NULL_TARGETS:
                    continue
                if GLOB_CHARS & set(target):
                    return gp.block(f"role '{role}': wildcard in redirection target '{target}'")
                reason = gp.path_verdict(cfg, rules, role, resolve(cwd, target))
                if reason:
                    return gp.block(f"{reason} (shell redirection)")

            while words and ASSIGNMENT.match(words[0]):
                name = words[0].split("=", 1)[0]
                if name not in env_allow:
                    return gp.block(f"role '{role}': environment variable '{name}' is not allowed")
                words = words[1:]
            if not words:
                return gp.block(f"role '{role}': assignment without a command")

            if words[0] == "cd":
                if len(pipeline) != 1 or len(words) != 2:
                    return gp.block(f"role '{role}': use 'cd <dir>' on its own, joined with &&")
                target = resolve(cwd, words[1])
                if gp.relative_to_root(target) is None:
                    return gp.block(f"role '{role}': cannot cd outside the project ({words[1]})")
                cwd = os.path.realpath(target)
                continue

            reason = command_reason(words, cwd, cfg, policy, readonly)
            if reason:
                return gp.block(
                    f"role '{role}': {reason}. Allowed: {allowed_summary(cfg, policy, readonly)}. "
                    "Do not work around this guard; report what you needed in your handback."
                )
    return 0


def main():
    return gp.run(check)


if __name__ == "__main__":
    sys.exit(main())
