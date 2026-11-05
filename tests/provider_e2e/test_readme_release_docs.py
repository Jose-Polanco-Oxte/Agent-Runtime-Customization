from pathlib import Path
import re
import tempfile
import tomllib
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"
CARGO_TOML_PATH = REPO_ROOT / "Cargo.toml"

MAX_README_LINES = 250

REQUIRED_LOCAL_FILE_LINKS = {
    "install.ps1",
    "install.sh",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "docs/USAGE.md",
    "docs/ARCHITECTURE.md",
    "docs/ROADMAP.md",
    "examples/README.md",
}

FORBIDDEN_ALPHA_PHRASES = (
    "1.0.0-alpha",
    "alpha software",
    "Arc is a prerelease",
    "between alpha releases",
    "not yet in the repository",
    "does not declare a license yet",
    "intended to be dual-licensed",
)


def github_heading_slug(title: str) -> str:
    cleaned = title.strip().replace("`", "")
    cleaned = re.sub(r"[^a-z0-9\s-]", "", cleaned.lower())
    cleaned = re.sub(r"\s+", "-", cleaned.strip())
    return cleaned


def strip_fenced_code_blocks(markdown_text: str) -> list[tuple[int, str]]:
    """Return (1-based line_number, line_text) for lines outside fenced code blocks."""
    result: list[tuple[int, str]] = []
    in_fence = False
    for idx, line in enumerate(markdown_text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            result.append((idx, line))
    return result


def extract_headings(markdown_text: str) -> list[dict[str, object]]:
    """Extract markdown headings (#, ##, ###) outside fenced code blocks."""
    headings: list[dict[str, object]] = []
    heading_re = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
    for line_no, line in strip_fenced_code_blocks(markdown_text):
        match = heading_re.match(line)
        if match:
            level = len(match.group(1))
            title = match.group(2).strip()
            headings.append(
                {
                    "line": line_no,
                    "level": level,
                    "title": title,
                    "slug": github_heading_slug(title),
                }
            )
    return headings


def extract_toc_entries(markdown_text: str) -> list[dict[str, object]]:
    """Extract Table of Contents entries under the **Contents** block."""
    lines = markdown_text.splitlines()
    toc_start = None
    for idx, line in enumerate(lines):
        if line.strip() == "**Contents**":
            toc_start = idx + 1
            break
    if toc_start is None:
        raise ValueError("README is missing the '**Contents**' Table of Contents header")

    entries: list[dict[str, object]] = []
    toc_item_re = re.compile(r"^(\s*)-\s+\[([^\]]+)\]\(#([^)]+)\)\s*$")
    for idx in range(toc_start, len(lines)):
        line = lines[idx]
        if not line.strip():
            if entries:
                break
            continue
        if line.startswith("#"):
            break
        match = toc_item_re.match(line)
        if not match:
            raise ValueError(f"Invalid Table of Contents line {idx + 1}: {line!r}")
        indent = len(match.group(1))
        if indent % 2 != 0:
            raise ValueError(f"Table of Contents line {idx + 1} has odd indentation: {indent}")
        entries.append(
            {
                "line": idx + 1,
                "level": (indent // 2) + 1,
                "title": match.group(2).strip(),
                "slug": match.group(3).strip(),
            }
        )

    if not entries:
        raise ValueError("Table of Contents under '**Contents**' has no entries")
    return entries


def extract_section(markdown_text: str, heading_line: str) -> str:
    """Return the content under a specific markdown heading up to the next heading of same or higher level."""
    target_match = re.match(r"^(#{1,6})\s+(.+?)\s*$", heading_line.strip())
    if not target_match:
        raise ValueError(f"Invalid heading selector: {heading_line!r}")
    target_level = len(target_match.group(1))
    target_title = target_match.group(2).strip()

    lines = markdown_text.splitlines()
    in_fence = False
    start_idx = None
    end_idx = len(lines)
    heading_re = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

    for idx, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = heading_re.match(line)
        if not match:
            continue
        level = len(match.group(1))
        title = match.group(2).strip()
        if start_idx is None:
            if level == target_level and title == target_title:
                start_idx = idx + 1
        else:
            if level <= target_level:
                end_idx = idx
                break

    if start_idx is None:
        raise ValueError(f"Section {heading_line!r} not found in markdown document")
    return "\n".join(lines[start_idx:end_idx]).strip()


def extract_markdown_links(markdown_text: str) -> list[tuple[int, str, str]]:
    """Return (line_number, label, target) for markdown links outside fenced code blocks."""
    links: list[tuple[int, str, str]] = []
    badge_link_re = re.compile(r"\[!\[([^\]]*)\]\([^)]+\)\]\(([^)\s]+)\)")
    text_link_re = re.compile(r"(?<!!)\[([^\[\]]+)\]\(([^)\s]+)\)")

    for line_no, line in strip_fenced_code_blocks(markdown_text):
        for match in badge_link_re.finditer(line):
            links.append((line_no, match.group(1), match.group(2)))
        scrubbed = badge_link_re.sub("", line)
        for match in text_link_re.finditer(scrubbed):
            links.append((line_no, match.group(1), match.group(2)))
    return links


def validate_readme_content(
    markdown_text: str,
    repo_root: Path,
    required_local_links: set[str] | None = None,
) -> None:
    """Validate README.md line budget, ToC parity, local links, version 1.0.0, and license/install docs."""
    lines = markdown_text.splitlines()
    if len(lines) == 0:
        raise ValueError("README.md must not be empty")
    if len(lines) > MAX_README_LINES:
        raise ValueError(
            f"README.md exceeds {MAX_README_LINES}-line budget: got {len(lines)} lines"
        )

    headings = extract_headings(markdown_text)
    toc_entries = extract_toc_entries(markdown_text)

    expected_toc = [
        {"level": h["level"], "title": h["title"], "slug": h["slug"]}
        for h in headings
    ]
    actual_toc = [
        {"level": t["level"], "title": t["title"], "slug": t["slug"]}
        for t in toc_entries
    ]
    if actual_toc != expected_toc:
        raise ValueError(
            f"Table of Contents does not match headings: toc={actual_toc!r} vs headings={expected_toc!r}"
        )

    heading_slugs = {str(h["slug"]) for h in headings}
    links = extract_markdown_links(markdown_text)
    seen_local_files: set[str] = set()
    errors: list[str] = []

    for line_no, _label, target in links:
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        if target.startswith("#"):
            slug = target[1:]
            if slug not in heading_slugs:
                errors.append(
                    f"Broken anchor link '#{slug}' at line {line_no}; valid slugs: {sorted(heading_slugs)}"
                )
            continue

        file_part = target.split("#", 1)[0]
        if not file_part:
            continue
        resolved = (repo_root / file_part).resolve()
        try:
            resolved.relative_to(repo_root.resolve())
        except ValueError:
            errors.append(
                f"Local link {target!r} at line {line_no} escapes repository root"
            )
            continue
        if not resolved.exists():
            errors.append(
                f"Broken local file link {target!r} at line {line_no}: {resolved} does not exist"
            )
            continue
        seen_local_files.add(Path(file_part).as_posix())

    expected_links = (
        REQUIRED_LOCAL_FILE_LINKS if required_local_links is None else required_local_links
    )
    missing_links = sorted(expected_links - seen_local_files)
    if missing_links:
        errors.append(
            f"README.md is missing required local markdown links: {', '.join(missing_links)}"
        )

    for phrase in FORBIDDEN_ALPHA_PHRASES:
        if phrase in markdown_text:
            errors.append(
                f"README.md contains outdated prerelease or license placeholder text: {phrase!r}"
            )

    if errors:
        raise ValueError("; ".join(errors))


class TestReadmeReleaseDocs(unittest.TestCase):
    """Verification suite for REQ-006: README.md v1.0.0 release, installer, and license documentation."""

    def test_install_section_documents_prebuilt_installers_and_source_builds(self) -> None:
        self.assertTrue(README_PATH.is_file(), "README.md must exist at the repository root")
        readme_text = README_PATH.read_text(encoding="utf-8")
        install_section = extract_section(readme_text, "## Install")
        install_links = {
            Path(target.split("#", 1)[0]).as_posix()
            for _line, _label, target in extract_markdown_links(install_section)
            if not target.startswith(("http://", "https://", "mailto:", "#"))
        }

        self.assertIn(
            "install.ps1",
            install_links,
            "## Install must link to [install.ps1](install.ps1) for Windows prebuilt release installation",
        )
        self.assertIn(
            "install.sh",
            install_links,
            "## Install must link to [install.sh](install.sh) for Linux/macOS prebuilt release installation",
        )
        self.assertIn("SHA256SUMS", install_section)
        self.assertIn("-InstallDir", install_section)
        self.assertIn("--install-dir", install_section)
        self.assertIn("-NoModifyPath", install_section)
        self.assertIn("--no-modify-path", install_section)

        self.assertIn("build.ps1", install_section)
        self.assertIn("build.sh", install_section)
        self.assertRegex(install_section, r"build\.ps1\s+-Install")
        self.assertRegex(install_section, r"\./build\.sh\s+--install")
        self.assertIn("arc-decision-ui-host", install_section)

    def test_version_references_aligned_to_1_0_0_without_alpha_prerelease(self) -> None:
        readme_text = README_PATH.read_text(encoding="utf-8")
        cargo_manifest = tomllib.loads(CARGO_TOML_PATH.read_text(encoding="utf-8"))
        cargo_version = cargo_manifest["package"]["version"]
        self.assertEqual(cargo_version, "1.0.0")

        for phrase in (
            "1.0.0-alpha",
            "alpha software",
            "Arc is a prerelease",
            "between alpha releases",
        ):
            self.assertNotIn(
                phrase,
                readme_text,
                f"README.md must not contain leftover alpha reference {phrase!r}",
            )

        self.assertIn("version-1.0.0", readme_text)
        install_section = extract_section(readme_text, "## Install")
        self.assertIn(
            "arc 1.0.0",
            install_section,
            "## Install must document `arc --version` printing `arc 1.0.0`",
        )

        versioning_section = extract_section(readme_text, "### Versioning")
        self.assertIn("1.0.0", versioning_section)
        self.assertIn("Cargo.toml", versioning_section)
        self.assertNotIn("alpha", versioning_section.lower())

    def test_license_section_declares_dual_mit_or_apache_2_0_with_links(self) -> None:
        readme_text = README_PATH.read_text(encoding="utf-8")
        license_section = extract_section(readme_text, "## License")
        license_links = {
            Path(target.split("#", 1)[0]).as_posix()
            for _line, _label, target in extract_markdown_links(license_section)
            if not target.startswith(("http://", "https://", "mailto:", "#"))
        }

        self.assertIn(
            "LICENSE-MIT",
            license_links,
            "## License must link to [LICENSE-MIT](LICENSE-MIT)",
        )
        self.assertIn(
            "LICENSE-APACHE",
            license_links,
            "## License must link to [LICENSE-APACHE](LICENSE-APACHE)",
        )
        self.assertTrue((REPO_ROOT / "LICENSE-MIT").is_file())
        self.assertTrue((REPO_ROOT / "LICENSE-APACHE").is_file())

        self.assertIn("MIT", license_section)
        self.assertIn("Apache", license_section)
        for outdated in (
            "not yet in the repository",
            "does not declare a license yet",
            "intended to be dual-licensed",
        ):
            self.assertNotIn(
                outdated,
                license_section,
                f"## License must not contain outdated statement {outdated!r}",
            )

    def test_readme_line_budget_toc_parity_and_local_link_integrity(self) -> None:
        readme_text = README_PATH.read_text(encoding="utf-8")
        lines = readme_text.splitlines()
        self.assertGreater(len(lines), 0)
        self.assertLessEqual(
            len(lines),
            MAX_README_LINES,
            f"README.md must stay at or under {MAX_README_LINES} lines (got {len(lines)})",
        )

        headings = extract_headings(readme_text)
        toc_entries = extract_toc_entries(readme_text)
        self.assertEqual(
            [(t["level"], t["title"], t["slug"]) for t in toc_entries],
            [(h["level"], h["title"], h["slug"]) for h in headings],
            "Table of Contents under **Contents** must match all headings in README.md",
        )

        try:
            validate_readme_content(readme_text, REPO_ROOT)
        except ValueError as exc:
            self.fail(str(exc))

    def test_validator_rejects_malformed_readme_fixtures_and_validates_repo_readme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            for rel_file in ("install.ps1", "install.sh", "LICENSE-MIT", "LICENSE-APACHE"):
                path = tmp_root / rel_file
                path.write_text("fixture\n", encoding="utf-8")

            valid_doc = "\n".join(
                [
                    "# Sample Title",
                    "",
                    "**Contents**",
                    "",
                    "- [Sample Title](#sample-title)",
                    "  - [Install](#install)",
                    "  - [License](#license)",
                    "",
                    "## Install",
                    "Use [install.ps1](install.ps1) or [install.sh](install.sh).",
                    "",
                    "## License",
                    "Dual-licensed under MIT OR Apache-2.0: [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).",
                ]
            )
            required_subset = {"install.ps1", "install.sh", "LICENSE-MIT", "LICENSE-APACHE"}
            validate_readme_content(valid_doc, tmp_root, required_local_links=required_subset)

            too_long_doc = valid_doc + ("\nline" * 250)
            with self.assertRaisesRegex(ValueError, "exceeds 250-line budget"):
                validate_readme_content(too_long_doc, tmp_root, required_local_links=required_subset)

            mismatched_toc_doc = valid_doc.replace(
                "  - [Install](#install)", "  - [Setup](#setup)"
            )
            with self.assertRaisesRegex(ValueError, "Table of Contents does not match headings"):
                validate_readme_content(
                    mismatched_toc_doc, tmp_root, required_local_links=required_subset
                )

            broken_anchor_doc = valid_doc + "\nSee [missing section](#does-not-exist)."
            with self.assertRaisesRegex(ValueError, "Broken anchor link '#does-not-exist'"):
                validate_readme_content(
                    broken_anchor_doc, tmp_root, required_local_links=required_subset
                )

            broken_file_doc = valid_doc + "\nSee [missing file](docs/NONEXISTENT.md)."
            with self.assertRaisesRegex(ValueError, "Broken local file link 'docs/NONEXISTENT.md'"):
                validate_readme_content(
                    broken_file_doc, tmp_root, required_local_links=required_subset
                )

            alpha_leftover_doc = valid_doc + "\nPrints `arc 1.0.0-alpha.13`."
            with self.assertRaisesRegex(ValueError, "1.0.0-alpha"):
                validate_readme_content(
                    alpha_leftover_doc, tmp_root, required_local_links=required_subset
                )

        readme_text = README_PATH.read_text(encoding="utf-8")
        try:
            validate_readme_content(readme_text, REPO_ROOT)
        except ValueError as exc:
            self.fail(str(exc))


if __name__ == "__main__":
    unittest.main()
