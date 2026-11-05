"""Deterministic lexical inventory; references are candidates, not reachability proof."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("src", "ui/decision/src", "ui/decision/src-tauri/src")
DECLARATION = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+|export\s+)?"
    r"(?:async\s+)?(?:struct|enum|type|trait|fn|const|mod|interface|function|class)\s+"
    r"([A-Za-z_][A-Za-z_0-9]*)"
)
VERSIONED = re.compile(r"(?:V\d+|_v\d+|_V\d+)$")
# Preserve offsets/newlines while excluding comments and quoted contents.
LEXEME = re.compile(
    r'/\*[\s\S]*?\*/|//[^\n]*|r(?P<hash>\#*)"[\s\S]*?"(?P=hash)'
    r'|"(?:\\[\s\S]|[^"\\])*"|\x27(?:\\.|[^\x27\\\n])\x27'
)


def blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group())


def production(text: str) -> str:
    code = LEXEME.sub(blank, text)
    # Rust inline test modules/items are not production consumers.
    for match in reversed(list(re.finditer(r"#\[cfg\(test\)\]", code))):
        start = code.find("{", match.end())
        terminator = code.find(";", match.end())
        if terminator >= 0 and (start < 0 or terminator < start):
            end = terminator + 1
            code = code[:match.start()] + re.sub(r"[^\n]", " ", code[match.start():end]) + code[end:]
            continue
        if start < 0:
            continue
        depth, end = 1, start + 1
        while end < len(code) and depth:
            depth += (code[end] == "{") - (code[end] == "}")
            end += 1
        code = code[:match.start()] + re.sub(r"[^\n]", " ", code[match.start():end]) + code[end:]
    return code


def inventory() -> dict[str, object]:
    files: dict[str, str] = {}
    test_files: dict[str, str] = {}
    for directory in (*SOURCE_ROOTS, "tests", "examples"):
        for path in sorted((ROOT / directory).rglob("*")):
            if path.suffix not in (".rs", ".ts", ".svelte"):
                continue
            name = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8-sig")
            if directory in ("tests", "examples") or path.name.endswith(".test.ts") or path.name == "vitest-setup.ts":
                test_files[name] = LEXEME.sub(blank, text)
            else:
                files[name] = production(text)
                test_files[name] = LEXEME.sub(blank, text)
    index: dict[str, list[dict[str, object]]] = defaultdict(list)
    support_index: dict[str, set[str]] = defaultdict(set)
    token_pattern = re.compile(r"\b[A-Za-z_][A-Za-z_0-9]*\b")
    for name, code in files.items():
        for line_number, line in enumerate(code.splitlines(), 1):
            for token in token_pattern.finditer(line):
                index[token.group()].append({"path": name, "line": line_number})
    for name, code in test_files.items():
        extra = Counter(token_pattern.findall(code)) - Counter(token_pattern.findall(files.get(name, "")))
        for symbol in extra:
            support_index[symbol].add(name)
    declarations = []
    for name, code in sorted(files.items()):
        for match in DECLARATION.finditer(code):
            symbol = match[1]
            if not VERSIONED.search(symbol):
                continue
            line = code.count("\n", 0, match.start(1)) + 1
            references = [r for r in index[symbol] if r != {"path": name, "line": line}]
            support = sorted(support_index[symbol])
            declarations.append({"symbol": symbol, "path": name, "line": line,
                                 "production_mentions": references, "test_or_example_files": support})
    return {"source_files": len(files), "versioned_declarations": declarations,
            "limitations": "Lexical mentions include definitions/impls/reexports; they do not prove a call from main. cfg other than test is included. Generated code and dependencies excluded. Review call paths and compile after deletion."}


def check_bridge() -> list[str]:
    host = ROOT / "ui/decision/src-tauri"
    bridge = (ROOT / "ui/decision/src/lib/tauri-bridge.ts").read_text(encoding="utf-8")
    invoked = set(re.findall(r'\binvoke(?:<[^>]+>)?\(\s*"([a-z_]+)"', bridge))
    manifest = (host / "src/command_manifest.rs").read_text(encoding="utf-8")
    declared = set(re.findall(r'"([a-z_]+)"', manifest))
    source = production((host / "src/lib.rs").read_text(encoding="utf-8"))
    handlers = re.findall(r'generate_handler!\[([^\]]+)\]', source)
    if len(handlers) != 1 or not invoked or not declared:
        return ["Bridge inventory could not locate a nonempty invoke/manifest/handler contract."]
    registered = set(re.findall(r"\b[a-z_]+\b(?!::)", handlers[0]))
    capability = json.loads((host / "capabilities/decision.json").read_text(encoding="utf-8"))
    permitted: set[str] = set()
    permissions: dict[str, list[str]] = {}
    for path in sorted((host / "permissions").rglob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        for permission in data.get("permission", []):
            permissions[permission["identifier"]] = permission.get("commands", {}).get("allow", [])
    for identifier in capability["permissions"]:
        if identifier not in permissions:
            return [f"Missing local permission definition: {identifier}"]
        permitted.update(permissions[identifier])
    errors = []
    for label, actual in (("manifest", declared), ("handler", registered), ("capability", permitted)):
        if actual != invoked:
            errors.append(f"{label}: missing={sorted(invoked - actual)}, extra={sorted(actual - invoked)}")
    errors.extend(check_view_model())
    return errors


def check_view_model() -> list[str]:
    """Compare field sets of the current plain struct/interface payload graph."""
    rust = production((ROOT / "ui/decision/src-tauri/src/lib.rs").read_text(encoding="utf-8"))
    rust += production((ROOT / "src/runtime/guard_evaluation.rs").read_text(encoding="utf-8"))
    typescript = production((ROOT / "ui/decision/src/lib/contracts.ts").read_text(encoding="utf-8"))

    def fields(source: str, kind: str, name: str) -> dict[str, str] | None:
        match = re.search(r"\b" + kind + r"\s+" + re.escape(name) + r"\s*\{([^}]+)\}", source)
        if not match:
            return None
        pattern = (r"^\s*(?:pub\s+)?(\w+)\s*:\s*([^,\n]+)," if kind == "struct"
                   else r"^\s*(\w+)\??\s*:\s*([^;\n]+);")
        result = dict(re.findall(pattern, match[1], re.MULTILINE))
        return result or None

    pending = [("DecisionViewModel", "DecisionViewModel")]
    visited: set[tuple[str, str]] = set()
    errors = []
    while pending:
        pair = pending.pop()
        if pair in visited:
            continue
        visited.add(pair)
        left, right = fields(rust, "struct", pair[0]), fields(typescript, "interface", pair[1])
        if left is None or right is None:
            errors.append(f"Cannot inspect plain payload struct/interface: {pair}")
            continue
        if left.keys() != right.keys():
            errors.append(f"Payload {pair}: Rust-only={sorted(left.keys() - right.keys())}, TS-only={sorted(right.keys() - left.keys())}")
        for key in sorted(left.keys() & right.keys()):
            rust_name = re.sub(r"^(?:Option|Vec)<(.+)>$", r"\1", left[key].strip())
            ts_name = right[key].strip().removesuffix("[]")
            rust_child, ts_child = fields(rust, "struct", rust_name), fields(typescript, "interface", ts_name)
            if rust_child is not None or ts_child is not None:
                pending.append((rust_name, ts_name))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write stable JSON instead of stdout")
    parser.add_argument("--check-bridge", action="store_true", help="Fail on payload fields or literal invoke/handler/manifest/ACL drift")
    args = parser.parse_args()
    data = inventory()
    errors = check_bridge() if args.check_bridge else []
    if args.check_bridge:
        data["bridge_errors"] = errors
    result = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
