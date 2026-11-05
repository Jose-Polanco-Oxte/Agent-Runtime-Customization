import hashlib
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"


def _load_workflow_text() -> str:
    if not RELEASE_WORKFLOW_PATH.is_file():
        raise AssertionError(
            f"Expected release workflow at {RELEASE_WORKFLOW_PATH}, but file does not exist"
        )
    content = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    if not content.strip():
        raise AssertionError("release.yml must not be empty")
    return content


def _extract_top_level_block(text: str, key: str) -> str:
    """Extract a top-level YAML mapping block starting with `<key>:` up to the next top-level key."""
    lines = text.splitlines()
    start_idx = None
    key_pattern = re.compile(rf"^(?:['\"]?{re.escape(key)}['\"]?)\s*:")
    top_level_key_pattern = re.compile(r"^[A-Za-z0-9_'\"]+\s*:")

    for idx, line in enumerate(lines):
        if key_pattern.match(line):
            start_idx = idx
            break
    if start_idx is None:
        return ""

    collected = [lines[start_idx]]
    for line in lines[start_idx + 1 :]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and top_level_key_pattern.match(line):
            break
        collected.append(line)
    return "\n".join(collected)


def _extract_jobs(text: str) -> dict[str, str]:
    """Extract job blocks (2-space indented under top-level `jobs:`) as `{job_name: job_block_text}`."""
    jobs_block = _extract_top_level_block(text, "jobs")
    if not jobs_block:
        return {}
    lines = jobs_block.splitlines()[1:]
    jobs: dict[str, list[str]] = {}
    current_job: str | None = None
    job_header_re = re.compile(r"^  ([A-Za-z0-9_-]+)\s*:\s*(?:#.*)?$")

    for line in lines:
        match = job_header_re.match(line)
        if match:
            current_job = match.group(1)
            jobs[current_job] = [line]
        elif current_job is not None:
            jobs[current_job].append(line)

    return {name: "\n".join(body) for name, body in jobs.items()}


def _verify_tag_against_cargo_toml(tag_or_version: str, cargo_toml_path: Path) -> tuple[bool, str, str]:
    """Reference evaluator for tag-to-Cargo.toml version verification."""
    manifest = tomllib.loads(cargo_toml_path.read_text(encoding="utf-8"))
    cargo_version = manifest.get("package", {}).get("version", "")
    normalized = tag_or_version.strip()
    if normalized.startswith("refs/tags/"):
        normalized = normalized[len("refs/tags/") :]
    if not normalized.startswith("v"):
        return (False, normalized, cargo_version)
    tag_version = normalized[1:]
    return (
        bool(tag_version) and tag_version == cargo_version,
        tag_version,
        cargo_version,
    )


class TestReleaseWorkflow(unittest.TestCase):
    """Verification suite for REQ-002: tag-triggered multi-platform release pipeline."""

    def test_workflow_exists_and_triggers_on_v_tags_and_workflow_dispatch(self) -> None:
        text = _load_workflow_text()
        on_block = _extract_top_level_block(text, "on")
        self.assertTrue(on_block, "release.yml must define a top-level 'on:' trigger block")
        self.assertRegex(
            on_block,
            r"(?m)^\s*push\s*:",
            "release.yml 'on:' block must include 'push:' trigger",
        )
        self.assertRegex(
            on_block,
            r"(?m)^\s*tags\s*:",
            "release.yml 'push:' trigger must filter on 'tags:'",
        )
        self.assertRegex(
            on_block,
            r"['\"]?v\*['\"]?",
            "release.yml 'push.tags' must match 'v*'",
        )
        self.assertRegex(
            on_block,
            r"(?m)^\s*workflow_dispatch\s*:",
            "release.yml 'on:' block must include 'workflow_dispatch:'",
        )

    def test_workflow_enforces_least_privilege_permissions(self) -> None:
        text = _load_workflow_text()
        top_permissions = _extract_top_level_block(text, "permissions")
        self.assertTrue(
            top_permissions,
            "release.yml must declare top-level default 'permissions:'",
        )
        self.assertRegex(
            top_permissions,
            r"(?m)^\s*contents\s*:\s*read\b",
            "Top-level permissions must set 'contents: read'",
        )
        self.assertNotRegex(
            top_permissions,
            r"(?m)^\s*contents\s*:\s*write\b",
            "Top-level permissions must not grant 'contents: write'",
        )

        jobs = _extract_jobs(text)
        self.assertGreaterEqual(
            len(jobs),
            2,
            "release.yml must separate build and release publication jobs",
        )

        write_jobs = [
            name
            for name, block in jobs.items()
            if re.search(r"(?m)^\s*contents\s*:\s*write\b", block)
        ]
        self.assertEqual(
            len(write_jobs),
            1,
            f"Exactly one release publication job may grant 'contents: write', found: {write_jobs}",
        )
        release_job_name = write_jobs[0]
        for name, block in jobs.items():
            if name != release_job_name:
                self.assertNotRegex(
                    block,
                    r"(?m)^\s*contents\s*:\s*write\b",
                    f"Non-release job '{name}' must not grant 'contents: write'",
                )

    def test_workflow_verifies_tag_matches_cargo_toml_version_and_fails_fast(self) -> None:
        text = _load_workflow_text()
        self.assertIn(
            "Cargo.toml",
            text,
            "release.yml must inspect root Cargo.toml for version verification",
        )
        # Workflow must strip leading 'v' from tag / input version and compare against Cargo.toml version
        self.assertTrue(
            re.search(r"GITHUB_REF_NAME|github\.ref_name|inputs\.", text),
            "release.yml must read the tag or dispatch version from github.ref_name / GITHUB_REF_NAME / inputs",
        )
        self.assertTrue(
            re.search(r"exit\s+1|sys\.exit\(\s*1\s*\)|throw\b|Write-Error", text),
            "release.yml version check must fail fast with non-zero exit on mismatch",
        )

        # Deterministic verification against the repository's actual Cargo.toml (1.0.0)
        cargo_toml = REPO_ROOT / "Cargo.toml"
        ok_match, tag_ver, cargo_ver = _verify_tag_against_cargo_toml("v1.0.0", cargo_toml)
        self.assertTrue(ok_match, "Tag v1.0.0 must match Cargo.toml version 1.0.0")
        self.assertEqual(tag_ver, "1.0.0")
        self.assertEqual(cargo_ver, "1.0.0")

        ok_mismatch, bad_ver, _ = _verify_tag_against_cargo_toml("v2.0.0", cargo_toml)
        self.assertFalse(ok_mismatch, "Mismatched tag v2.0.0 must be rejected")
        self.assertEqual(bad_ver, "2.0.0")

        ok_no_prefix, _, _ = _verify_tag_against_cargo_toml("1.0.0", cargo_toml)
        self.assertFalse(ok_no_prefix, "Tag without leading 'v' prefix must be rejected")

    def test_workflow_builds_frontend_sidecar_and_cli_across_all_four_targets(self) -> None:
        text = _load_workflow_text()
        expected_targets = (
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        )
        for target in expected_targets:
            self.assertIn(
                target,
                text,
                f"release.yml target matrix must include '{target}'",
            )

        # Frontend build in ui/decision
        self.assertTrue(
            re.search(
                r"npm\s+--prefix\s+ui/decision\s+ci\s+--ignore-scripts|working-directory\s*:\s*ui/decision[\s\S]*?npm\s+ci\s+--ignore-scripts",
                text,
            ),
            "release.yml must install frontend dependencies with 'npm ci --ignore-scripts' in ui/decision",
        )
        self.assertTrue(
            re.search(
                r"npm\s+--prefix\s+ui/decision\s+run\s+build|working-directory\s*:\s*ui/decision[\s\S]*?npm\s+run\s+build",
                text,
            ),
            "release.yml must build frontend assets with 'npm run build' in ui/decision",
        )

        # Sidecar build with custom-protocol feature and --release --locked
        self.assertIn(
            "arc-decision-ui-host",
            text,
            "release.yml must build the arc-decision-ui-host sidecar crate",
        )
        self.assertIn(
            "arc-decision-ui-host/custom-protocol",
            text,
            "release.yml must enable '--features arc-decision-ui-host/custom-protocol'",
        )
        self.assertRegex(
            text,
            r"cargo\s+build[^\n]*--release[^\n]*--locked|cargo\s+build[^\n]*--locked[^\n]*--release",
            "release.yml must build Rust binaries with both --release and --locked",
        )
        self.assertRegex(
            text,
            r"cargo\s+build[^\n]*-p\s+arc\b[^\n]*--bin\s+arc\b|cargo\s+build[^\n]*--bin\s+arc\b[^\n]*-p\s+arc\b",
            "release.yml must build the 'arc' CLI binary (-p arc --bin arc)",
        )

        # Linux Tauri system dependencies check
        self.assertIn(
            "libwebkit2gtk-4.1-dev",
            text,
            "Linux release job must install libwebkit2gtk-4.1-dev for Tauri build",
        )

    def test_workflow_packages_flat_zip_and_tar_gz_archives_with_required_files(self) -> None:
        text = _load_workflow_text()
        required_files = (
            "arc-decision-ui-host",
            "LICENSE-MIT",
            "LICENSE-APACHE",
            "README.md",
        )
        for req_file in required_files:
            self.assertIn(
                req_file,
                text,
                f"release.yml archive packaging must include '{req_file}'",
            )

        self.assertRegex(
            text,
            r"arc-v(?:\$\{\{[^}]+\}\}|\$\{?[A-Za-z0-9_]+\}?)-[A-Za-z0-9_${}.-]+\.zip",
            "release.yml must package Windows release archive as arc-v<VERSION>-<TARGET>.zip",
        )
        self.assertRegex(
            text,
            r"arc-v(?:\$\{\{[^}]+\}\}|\$\{?[A-Za-z0-9_]+\}?)-[A-Za-z0-9_${}.-]+\.tar\.gz",
            "release.yml must package Unix release archives as arc-v<VERSION>-<TARGET>.tar.gz",
        )

        # Deterministic simulation of the flat archive contract (.zip and .tar.gz)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            win_archive = tmp_path / "arc-v1.0.0-x86_64-pc-windows-msvc.zip"
            unix_archive = tmp_path / "arc-v1.0.0-x86_64-unknown-linux-gnu.tar.gz"

            win_entries = [
                "arc.exe",
                "arc-decision-ui-host.exe",
                "LICENSE-MIT",
                "LICENSE-APACHE",
                "README.md",
            ]
            with zipfile.ZipFile(win_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for entry in win_entries:
                    zf.writestr(entry, f"fixture-{entry}")

            with zipfile.ZipFile(win_archive, "r") as zf:
                self.assertEqual(sorted(zf.namelist()), sorted(win_entries))
                self.assertTrue(all("/" not in name for name in zf.namelist()))

            unix_entries = [
                "arc",
                "arc-decision-ui-host",
                "LICENSE-MIT",
                "LICENSE-APACHE",
                "README.md",
            ]
            staging = tmp_path / "staging"
            staging.mkdir()
            for entry in unix_entries:
                (staging / entry).write_text(f"fixture-{entry}", encoding="utf-8")
            with tarfile.open(unix_archive, "w:gz") as tf:
                for entry in unix_entries:
                    tf.add(staging / entry, arcname=entry)

            with tarfile.open(unix_archive, "r:gz") as tf:
                names = tf.getnames()
                self.assertEqual(sorted(names), sorted(unix_entries))
                self.assertTrue(all("/" not in name for name in names))

    def test_workflow_generates_sha256sums_and_publishes_all_release_assets(self) -> None:
        text = _load_workflow_text()
        jobs = _extract_jobs(text)
        self.assertIn(
            "release",
            jobs,
            "release.yml must define a 'release' job for checksums and publication",
        )
        release_job = jobs["release"]

        self.assertRegex(
            release_job,
            r"(?m)^\s*needs\s*:\s*(?:\[\s*build\s*\]|build)\b",
            "The 'release' job must depend on 'build' ('needs: build')",
        )
        self.assertIn(
            "SHA256SUMS",
            release_job,
            "The 'release' job must generate and publish SHA256SUMS",
        )
        self.assertTrue(
            re.search(r"sha256sum|shasum\s+-a\s+256|Get-FileHash", release_job),
            "The 'release' job must compute SHA-256 checksums for the release archives",
        )
        self.assertIn(
            "install.ps1",
            release_job,
            "The 'release' job must publish install.ps1 to the GitHub Release",
        )
        self.assertIn(
            "install.sh",
            release_job,
            "The 'release' job must publish install.sh to the GitHub Release",
        )
        self.assertTrue(
            re.search(r"softprops/action-gh-release|gh\s+release\s+create|gh\s+release\s+upload", release_job),
            "The 'release' job must publish assets to GitHub Releases via action-gh-release or gh release",
        )

        # Verify SHA256SUMS line format (<64-hex-lowercase>  <archive_name>) across all 4 targets
        expected_archives = (
            "arc-v1.0.0-x86_64-pc-windows-msvc.zip",
            "arc-v1.0.0-x86_64-unknown-linux-gnu.tar.gz",
            "arc-v1.0.0-aarch64-apple-darwin.tar.gz",
            "arc-v1.0.0-x86_64-apple-darwin.tar.gz",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            lines = []
            for archive_name in expected_archives:
                p = tmp_path / archive_name
                p.write_bytes(f"payload-{archive_name}".encode("utf-8"))
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
                lines.append(f"{digest}  {archive_name}")
            sha256sums_content = "\n".join(lines) + "\n"
            for line in sha256sums_content.strip().splitlines():
                self.assertRegex(
                    line,
                    r"^[0-9a-f]{64}  arc-v1\.0\.0-(?:x86_64-pc-windows-msvc\.zip|(?:x86_64-unknown-linux-gnu|aarch64-apple-darwin|x86_64-apple-darwin)\.tar\.gz)$",
                )


if __name__ == "__main__":
    unittest.main()
