from pathlib import Path
import tempfile
import tomllib
import unittest
from typing import Any

try:
    import yaml as _pyyaml
except ImportError:
    _pyyaml = None


REPO_ROOT = Path(__file__).resolve().parents[2]
DEPENDABOT_PATH = REPO_ROOT / ".github" / "dependabot.yml"
CARGO_TOML_PATH = REPO_ROOT / "Cargo.toml"
TAURI_CARGO_TOML_PATH = REPO_ROOT / "ui" / "decision" / "src-tauri" / "Cargo.toml"
NPM_PACKAGE_JSON_PATH = REPO_ROOT / "ui" / "decision" / "package.json"
WORKFLOWS_DIR_PATH = REPO_ROOT / ".github" / "workflows"


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if not val:
        return None
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        return val[1:-1]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    if val.startswith("{") and val.endswith("}"):
        inner = val[1:-1].strip()
        if not inner:
            return {}
        result: dict[str, Any] = {}
        for entry in inner.split(","):
            if ":" not in entry:
                raise ValueError(f"Invalid inline YAML mapping entry: {entry!r}")
            k, v = entry.split(":", 1)
            result[str(_parse_scalar(k))] = _parse_scalar(v)
        return result
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
        return int(val)
    return val


def _tokenize_yaml_lines(text: str) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if "\t" in raw_line:
            raise ValueError("Tabs are not allowed in YAML indentation")
        cleaned = _strip_yaml_comment(raw_line)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned.strip()))
    return tokens


def _parse_yaml_block(
    tokens: list[tuple[int, str]], index: int, min_indent: int
) -> tuple[Any, int]:
    if index >= len(tokens):
        return None, index

    first_indent, first_content = tokens[index]
    if first_indent < min_indent:
        return None, index

    if first_content.startswith("- ") or first_content == "-":
        seq: list[Any] = []
        seq_indent = first_indent
        while index < len(tokens):
            indent, content = tokens[index]
            if indent < seq_indent:
                break
            if indent != seq_indent or not (content.startswith("- ") or content == "-"):
                break
            item_rest = content[1:].strip()
            index += 1
            if not item_rest:
                nested, index = _parse_yaml_block(tokens, index, seq_indent + 1)
                seq.append(nested)
            elif ":" in item_rest and not (
                item_rest.startswith('"') or item_rest.startswith("'")
            ):
                k, v = item_rest.split(":", 1)
                key = str(_parse_scalar(k))
                val_str = v.strip()
                item_dict: dict[str, Any] = {}
                if val_str:
                    item_dict[key] = _parse_scalar(val_str)
                else:
                    nested_val, index = _parse_yaml_block(
                        tokens, index, seq_indent + 1
                    )
                    item_dict[key] = nested_val
                if index < len(tokens) and tokens[index][0] > seq_indent:
                    extra, index = _parse_yaml_block(tokens, index, seq_indent + 1)
                    if isinstance(extra, dict):
                        item_dict.update(extra)
                    else:
                        raise ValueError("Expected mapping continuation in list item")
                seq.append(item_dict)
            else:
                seq.append(_parse_scalar(item_rest))
        return seq, index

    mapping: dict[str, Any] = {}
    map_indent = first_indent
    while index < len(tokens):
        indent, content = tokens[index]
        if indent < map_indent:
            break
        if indent != map_indent:
            raise ValueError(
                f"Unexpected indentation {indent} (expected {map_indent}) at {content!r}"
            )
        if content.startswith("- ") or content == "-":
            break
        if ":" not in content:
            raise ValueError(f"Expected key: value in YAML mapping, got {content!r}")
        k, v = content.split(":", 1)
        key = str(_parse_scalar(k))
        val_str = v.strip()
        index += 1
        if val_str:
            mapping[key] = _parse_scalar(val_str)
        else:
            nested_val, index = _parse_yaml_block(tokens, index, map_indent + 1)
            mapping[key] = nested_val
    return mapping, index


def parse_dependabot_yaml(text: str) -> dict[str, Any]:
    """Parse Dependabot v2 YAML using built-in strict parser (and cross-check with PyYAML if installed)."""
    if not text or not text.strip():
        raise ValueError("Dependabot YAML content must not be empty")
    tokens = _tokenize_yaml_lines(text)
    if not tokens:
        raise ValueError("Dependabot YAML contains no configuration statements")
    parsed, next_idx = _parse_yaml_block(tokens, 0, 0)
    if next_idx != len(tokens):
        raise ValueError(f"Unparsed trailing YAML content at token {tokens[next_idx]!r}")
    if not isinstance(parsed, dict):
        raise ValueError("Top-level Dependabot YAML document must be a mapping")
    if _pyyaml is not None:
        pyyaml_parsed = _pyyaml.safe_load(text)
        if pyyaml_parsed != parsed:
            raise ValueError(
                f"YAML parser mismatch between built-in and PyYAML: {parsed!r} != {pyyaml_parsed!r}"
            )
    return parsed


def load_dependabot_config(path: Path = DEPENDABOT_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise AssertionError(
            f"Expected Dependabot config at {path}, but file does not exist"
        )
    content = path.read_text(encoding="utf-8")
    return parse_dependabot_yaml(content)


def validate_dependabot_config(
    config: dict[str, Any], repo_root: Path = REPO_ROOT
) -> None:
    """Validate Dependabot v2 schema and project-specific contract (AC-005.1..AC-005.4)."""
    if not isinstance(config, dict):
        raise ValueError("Dependabot configuration must be a mapping")

    if config.get("version") != 2:
        raise ValueError(
            f"Dependabot 'version' must be integer 2, got {config.get('version')!r}"
        )

    updates = config.get("updates")
    if not isinstance(updates, list) or not updates:
        raise ValueError("Dependabot 'updates' must be a non-empty list")

    expected_ecosystems = {
        "cargo": {
            "directory": "/",
            "limit": 10,
            "prefix": "chore(deps)",
        },
        "npm": {
            "directory": "/ui/decision",
            "limit": 10,
            "prefix": "chore(deps)",
        },
        "github-actions": {
            "directory": "/",
            "limit": 5,
            "prefix": "ci(deps)",
        },
    }

    seen_ecosystems: dict[str, dict[str, Any]] = {}
    for idx, entry in enumerate(updates):
        if not isinstance(entry, dict):
            raise ValueError(f"updates[{idx}] must be a mapping")
        ecosystem = entry.get("package-ecosystem")
        if not isinstance(ecosystem, str) or not ecosystem:
            raise ValueError(f"updates[{idx}] is missing 'package-ecosystem'")
        if ecosystem in seen_ecosystems:
            raise ValueError(f"Duplicate package-ecosystem entry: {ecosystem!r}")
        seen_ecosystems[ecosystem] = entry

    if set(seen_ecosystems.keys()) != set(expected_ecosystems.keys()):
        raise ValueError(
            f"Expected ecosystems {sorted(expected_ecosystems.keys())}, got {sorted(seen_ecosystems.keys())}"
        )

    for ecosystem, rules in expected_ecosystems.items():
        entry = seen_ecosystems[ecosystem]

        directory = entry.get("directory")
        if directory != rules["directory"]:
            raise ValueError(
                f"Ecosystem {ecosystem!r} must use directory {rules['directory']!r}, got {directory!r}"
            )

        rel_dir = directory.lstrip("/")
        target_dir = repo_root / rel_dir if rel_dir else repo_root
        if not target_dir.is_dir():
            raise ValueError(
                f"Directory {directory!r} for ecosystem {ecosystem!r} does not exist at {target_dir}"
            )

        schedule = entry.get("schedule")
        if not isinstance(schedule, dict) or schedule.get("interval") != "weekly":
            raise ValueError(
                f"Ecosystem {ecosystem!r} must configure schedule.interval == 'weekly', got {schedule!r}"
            )

        limit = entry.get("open-pull-requests-limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit != rules["limit"]:
            raise ValueError(
                f"Ecosystem {ecosystem!r} must set open-pull-requests-limit to {rules['limit']}, got {limit!r}"
            )

        commit_message = entry.get("commit-message")
        if (
            not isinstance(commit_message, dict)
            or commit_message.get("prefix") != rules["prefix"]
        ):
            raise ValueError(
                f"Ecosystem {ecosystem!r} must set commit-message.prefix to {rules['prefix']!r}, got {commit_message!r}"
            )

        groups = entry.get("groups")
        if not isinstance(groups, dict) or not groups:
            raise ValueError(
                f"Ecosystem {ecosystem!r} must define a non-empty 'groups' mapping"
            )
        for group_name, group_spec in groups.items():
            if not isinstance(group_name, str) or not group_name.strip():
                raise ValueError(f"Invalid group name in {ecosystem!r}")
            if not isinstance(group_spec, dict) or not group_spec:
                raise ValueError(
                    f"Group {group_name!r} in {ecosystem!r} must be a non-empty mapping"
                )
            patterns = group_spec.get("patterns")
            update_types = group_spec.get("update-types")
            dependency_type = group_spec.get("dependency-type")
            has_valid_patterns = (
                isinstance(patterns, list)
                and len(patterns) > 0
                and all(isinstance(p, str) and bool(p.strip()) for p in patterns)
            )
            has_valid_update_types = (
                isinstance(update_types, list)
                and len(update_types) > 0
                and all(isinstance(u, str) and bool(u.strip()) for u in update_types)
            )
            has_valid_dep_type = isinstance(dependency_type, str) and bool(
                dependency_type.strip()
            )
            if not (has_valid_patterns or has_valid_update_types or has_valid_dep_type):
                raise ValueError(
                    f"Group {group_name!r} in {ecosystem!r} must specify non-empty patterns, update-types, or dependency-type"
                )


class TestDependabotConfig(unittest.TestCase):
    """Verification suite for REQ-005: Automated Dependabot configuration."""

    def test_dependabot_exists_version_2_and_ecosystems_match_manifests(self) -> None:
        """AC-005.1, AC-005.4: .github/dependabot.yml is valid v2 YAML with cargo (/), npm (/ui/decision), and github-actions (/)."""
        config = load_dependabot_config()
        self.assertEqual(
            config.get("version"),
            2,
            "dependabot.yml top-level 'version' must equal 2",
        )

        updates = config.get("updates")
        self.assertIsInstance(updates, list, "'updates' must be a YAML list")
        self.assertEqual(
            len(updates),
            3,
            "dependabot.yml must configure exactly 3 package ecosystems (cargo, npm, github-actions)",
        )

        by_ecosystem = {
            item.get("package-ecosystem"): item
            for item in updates
            if isinstance(item, dict)
        }
        self.assertEqual(
            set(by_ecosystem.keys()),
            {"cargo", "npm", "github-actions"},
            "dependabot.yml must configure cargo, npm, and github-actions ecosystems",
        )

        self.assertEqual(by_ecosystem["cargo"].get("directory"), "/")
        self.assertEqual(by_ecosystem["npm"].get("directory"), "/ui/decision")
        self.assertEqual(by_ecosystem["github-actions"].get("directory"), "/")

        # Verify each referenced directory and manifest exists in the repository
        self.assertTrue(
            CARGO_TOML_PATH.is_file(),
            f"Root Cargo.toml must exist at {CARGO_TOML_PATH} for cargo '/' updater",
        )
        self.assertTrue(
            NPM_PACKAGE_JSON_PATH.is_file(),
            f"Frontend package.json must exist at {NPM_PACKAGE_JSON_PATH} for npm '/ui/decision' updater",
        )
        self.assertTrue(
            WORKFLOWS_DIR_PATH.is_dir(),
            f"Workflows directory must exist at {WORKFLOWS_DIR_PATH} for github-actions '/' updater",
        )
        workflow_files = list(WORKFLOWS_DIR_PATH.glob("*.yml")) + list(
            WORKFLOWS_DIR_PATH.glob("*.yaml")
        )
        self.assertGreaterEqual(
            len(workflow_files),
            1,
            "At least one GitHub Actions workflow file must exist under .github/workflows/",
        )

    def test_dependabot_schedule_pr_limits_commit_prefixes_and_groups(self) -> None:
        """AC-005.2, AC-005.4: Each ecosystem sets weekly schedule, PR limits (10, 10, 5), commit prefixes, and non-empty groups."""
        config = load_dependabot_config()
        updates = config.get("updates", [])
        by_ecosystem = {
            item.get("package-ecosystem"): item
            for item in updates
            if isinstance(item, dict)
        }

        expected = {
            "cargo": {"limit": 10, "prefix": "chore(deps)"},
            "npm": {"limit": 10, "prefix": "chore(deps)"},
            "github-actions": {"limit": 5, "prefix": "ci(deps)"},
        }

        for ecosystem, spec in expected.items():
            self.assertIn(ecosystem, by_ecosystem, f"Missing {ecosystem} update entry")
            entry = by_ecosystem[ecosystem]

            schedule = entry.get("schedule")
            self.assertIsInstance(
                schedule, dict, f"{ecosystem} 'schedule' must be a mapping"
            )
            self.assertEqual(
                schedule.get("interval"),
                "weekly",
                f"{ecosystem} schedule.interval must be 'weekly'",
            )

            self.assertEqual(
                entry.get("open-pull-requests-limit"),
                spec["limit"],
                f"{ecosystem} open-pull-requests-limit must be {spec['limit']}",
            )

            commit_msg = entry.get("commit-message")
            self.assertIsInstance(
                commit_msg, dict, f"{ecosystem} 'commit-message' must be a mapping"
            )
            self.assertEqual(
                commit_msg.get("prefix"),
                spec["prefix"],
                f"{ecosystem} commit-message.prefix must be {spec['prefix']!r}",
            )

            groups = entry.get("groups")
            self.assertIsInstance(
                groups, dict, f"{ecosystem} 'groups' must be a mapping"
            )
            self.assertGreaterEqual(
                len(groups),
                1,
                f"{ecosystem} must define at least one dependency group to prevent PR noise",
            )
            for group_name, group_cfg in groups.items():
                self.assertIsInstance(
                    group_cfg,
                    dict,
                    f"Group {group_name!r} in {ecosystem} must be a mapping",
                )
                self.assertTrue(
                    bool(group_cfg.get("patterns"))
                    or bool(group_cfg.get("update-types"))
                    or bool(group_cfg.get("dependency-type")),
                    f"Group {group_name!r} in {ecosystem} must define patterns, update-types, or dependency-type",
                )

    def test_cargo_workspace_covers_root_and_tauri_sidecar_for_dependabot(self) -> None:
        """AC-005.3: Root Cargo.toml workspace covers '.' and 'ui/decision/src-tauri' and matches Dependabot cargo '/' directory."""
        config = load_dependabot_config()
        updates = config.get("updates", [])
        cargo_entries = [
            u
            for u in updates
            if isinstance(u, dict) and u.get("package-ecosystem") == "cargo"
        ]
        self.assertEqual(
            len(cargo_entries),
            1,
            "Dependabot must have a single root cargo updater covering the Cargo workspace",
        )
        self.assertEqual(cargo_entries[0].get("directory"), "/")

        root_manifest = tomllib.loads(CARGO_TOML_PATH.read_text(encoding="utf-8"))
        self.assertEqual(root_manifest.get("package", {}).get("name"), "arc")

        workspace = root_manifest.get("workspace")
        self.assertIsInstance(
            workspace, dict, "Root Cargo.toml must declare a [workspace] table"
        )
        members = workspace.get("members", [])
        default_members = workspace.get("default-members", [])
        self.assertIn(
            "ui/decision/src-tauri",
            members,
            "Root Cargo.toml [workspace].members must include 'ui/decision/src-tauri'",
        )
        self.assertIn(
            ".",
            default_members,
            "Root Cargo.toml [workspace].default-members must include '.'",
        )

        tauri_manifest = tomllib.loads(
            TAURI_CARGO_TOML_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            tauri_manifest.get("package", {}).get("name"),
            "arc-decision-ui-host",
            "Workspace member ui/decision/src-tauri/Cargo.toml must define 'arc-decision-ui-host'",
        )

    def test_validator_rejects_invalid_configs_and_accepts_repo_dependabot_yml(
        self,
    ) -> None:
        """AC-005.4: Automated schema validator rejects malformed Dependabot configs and accepts .github/dependabot.yml."""
        invalid_cases = [
            (
                "wrong version",
                """
version: 1
updates: []
""",
                "version",
            ),
            (
                "missing npm ecosystem",
                """
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      all:
        patterns:
          - "*"
""",
                "Expected ecosystems",
            ),
            (
                "wrong npm directory",
                """
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      rust:
        patterns:
          - "*"
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      web:
        patterns:
          - "*"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "ci(deps)"
    groups:
      actions:
        patterns:
          - "*"
""",
                "directory '/ui/decision'",
            ),
            (
                "non-weekly schedule",
                """
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      rust:
        patterns:
          - "*"
  - package-ecosystem: "npm"
    directory: "/ui/decision"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      web:
        patterns:
          - "*"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "ci(deps)"
    groups:
      actions:
        patterns:
          - "*"
""",
                "schedule.interval == 'weekly'",
            ),
            (
                "missing groups",
                """
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
  - package-ecosystem: "npm"
    directory: "/ui/decision"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    commit-message:
      prefix: "chore(deps)"
    groups:
      web:
        patterns:
          - "*"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    commit-message:
      prefix: "ci(deps)"
    groups:
      actions:
        patterns:
          - "*"
""",
                "non-empty 'groups'",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for label, yaml_text, expected_err in invalid_cases:
                candidate_file = tmp_path / "dependabot.yml"
                candidate_file.write_text(yaml_text.strip() + "\n", encoding="utf-8")
                parsed = load_dependabot_config(candidate_file)
                with self.assertRaises(
                    ValueError, msg=f"Invalid config ({label}) must be rejected"
                ) as ctx:
                    validate_dependabot_config(parsed, REPO_ROOT)
                self.assertIn(expected_err, str(ctx.exception))

        # Finally, validate the actual repository .github/dependabot.yml
        actual_config = load_dependabot_config(DEPENDABOT_PATH)
        validate_dependabot_config(actual_config, REPO_ROOT)


if __name__ == "__main__":
    unittest.main()
