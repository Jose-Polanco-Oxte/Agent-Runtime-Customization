import json
from pathlib import Path
import tomllib
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


class TestReleaseLicensing(unittest.TestCase):
    """Verification suite for REQ-001: dual MIT OR Apache-2.0 licensing and v1.0.0 metadata."""

    def test_license_mit_exists_non_empty_and_contains_canonical_clauses(self) -> None:
        license_mit = REPO_ROOT / "LICENSE-MIT"
        self.assertTrue(license_mit.is_file(), "LICENSE-MIT must exist at the repository root")
        content = license_mit.read_text(encoding="utf-8")
        self.assertGreater(len(content.strip()), 0, "LICENSE-MIT must not be empty")
        self.assertIn("MIT License", content)
        self.assertIn(
            "Permission is hereby granted, free of charge, to any person obtaining a copy",
            content,
        )
        self.assertIn(
            'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND',
            content,
        )

    def test_license_apache_exists_non_empty_and_contains_canonical_clauses(self) -> None:
        license_apache = REPO_ROOT / "LICENSE-APACHE"
        self.assertTrue(
            license_apache.is_file(),
            "LICENSE-APACHE must exist at the repository root",
        )
        content = license_apache.read_text(encoding="utf-8")
        self.assertGreater(len(content.strip()), 0, "LICENSE-APACHE must not be empty")
        self.assertIn("Apache License", content)
        self.assertIn("Version 2.0, January 2004", content)
        self.assertIn("http://www.apache.org/licenses/", content)
        self.assertIn(
            "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
            content,
        )

    def test_license_files_have_no_unresolved_template_placeholders(self) -> None:
        license_mit = REPO_ROOT / "LICENSE-MIT"
        license_apache = REPO_ROOT / "LICENSE-APACHE"
        self.assertTrue(license_mit.is_file(), "LICENSE-MIT must exist at the repository root")
        self.assertTrue(
            license_apache.is_file(),
            "LICENSE-APACHE must exist at the repository root",
        )
        mit_text = license_mit.read_text(encoding="utf-8").strip()
        apache_text = license_apache.read_text(encoding="utf-8").strip()
        self.assertGreaterEqual(
            len(mit_text),
            1000,
            "LICENSE-MIT must contain the full MIT license text",
        )
        self.assertGreaterEqual(
            len(apache_text),
            8000,
            "LICENSE-APACHE must contain the full Apache-2.0 license text",
        )
        forbidden_placeholders = (
            "[yyyy]",
            "[name of copyright owner]",
            "<year>",
            "<copyright holders>",
        )
        for placeholder in forbidden_placeholders:
            self.assertNotIn(placeholder, mit_text)
            self.assertNotIn(placeholder, apache_text)

    def test_root_cargo_toml_declares_dual_mit_or_apache_2_0_license(self) -> None:
        cargo_toml_path = REPO_ROOT / "Cargo.toml"
        manifest = tomllib.loads(cargo_toml_path.read_text(encoding="utf-8"))
        package = manifest.get("package", {})
        self.assertEqual(package.get("license"), "MIT OR Apache-2.0")

    def test_tauri_host_cargo_toml_declares_dual_mit_or_apache_2_0_license(self) -> None:
        tauri_cargo_path = REPO_ROOT / "ui" / "decision" / "src-tauri" / "Cargo.toml"
        manifest = tomllib.loads(tauri_cargo_path.read_text(encoding="utf-8"))
        package = manifest.get("package", {})
        self.assertEqual(package.get("license"), "MIT OR Apache-2.0")

    def test_cargo_manifests_have_identical_spdx_license_expression(self) -> None:
        manifest_paths = (
            REPO_ROOT / "Cargo.toml",
            REPO_ROOT / "ui" / "decision" / "src-tauri" / "Cargo.toml",
        )
        licenses = {}
        for path in manifest_paths:
            rel = path.relative_to(REPO_ROOT).as_posix()
            manifest = tomllib.loads(path.read_text(encoding="utf-8"))
            pkg = manifest.get("package", {})
            self.assertIn("license", pkg, f"{rel} [package] must declare a license field")
            licenses[rel] = pkg["license"]

        self.assertEqual(
            licenses,
            {
                "Cargo.toml": "MIT OR Apache-2.0",
                "ui/decision/src-tauri/Cargo.toml": "MIT OR Apache-2.0",
            },
        )

    def test_all_release_manifests_align_to_version_1_0_0_without_alpha_suffix(self) -> None:
        root_cargo = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        tauri_cargo = tomllib.loads(
            (REPO_ROOT / "ui" / "decision" / "src-tauri" / "Cargo.toml").read_text(
                encoding="utf-8"
            )
        )
        package_json = json.loads(
            (REPO_ROOT / "ui" / "decision" / "package.json").read_text(encoding="utf-8")
        )
        tauri_conf = json.loads(
            (REPO_ROOT / "ui" / "decision" / "src-tauri" / "tauri.conf.json").read_text(
                encoding="utf-8"
            )
        )

        versions = {
            "Cargo.toml": root_cargo.get("package", {}).get("version"),
            "ui/decision/src-tauri/Cargo.toml": tauri_cargo.get("package", {}).get("version"),
            "ui/decision/package.json": package_json.get("version"),
            "ui/decision/src-tauri/tauri.conf.json": tauri_conf.get("version"),
        }

        for manifest_rel, version in versions.items():
            self.assertIsInstance(version, str, f"{manifest_rel} must have a string version")
            self.assertNotIn(
                "-alpha",
                version,
                f"{manifest_rel} must not contain leftover -alpha suffix",
            )
            self.assertEqual(
                version,
                "1.0.0",
                f"{manifest_rel} version must be aligned to 1.0.0",
            )


if __name__ == "__main__":
    unittest.main()
