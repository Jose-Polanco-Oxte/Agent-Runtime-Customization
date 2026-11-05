import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1_PATH = REPO_ROOT / "install.ps1"
ARCHIVE_NAME = "arc-v1.0.0-x86_64-pc-windows-msvc.zip"


def _find_powershell() -> str:
    for candidate in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("Neither powershell nor pwsh was found on PATH")


def _build_dummy_exe(output_path: Path) -> None:
    """Create a tiny standalone Windows .exe that prints 'arc 1.0.0' on --version and exits 0."""
    csc_candidates = [
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
    ]
    for csc in csc_candidates:
        if csc.is_file():
            cs_source = output_path.with_suffix(".cs")
            cs_source.write_text(
                "using System;\n"
                "public class Program {\n"
                "    public static int Main(string[] args) {\n"
                '        Console.WriteLine("arc 1.0.0");\n'
                "        return 0;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            try:
                proc = subprocess.run(
                    [
                        str(csc),
                        "/nologo",
                        "/target:exe",
                        f"/out:{output_path}",
                        str(cs_source),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if proc.returncode == 0 and output_path.is_file():
                    return
            finally:
                cs_source.unlink(missing_ok=True)

    for fallback in (
        REPO_ROOT / "target" / "release" / "arc.exe",
        REPO_ROOT / "target" / "debug" / "arc.exe",
        Path(r"C:\Windows\System32\tar.exe"),
        Path(r"C:\Windows\System32\curl.exe"),
    ):
        if fallback.is_file():
            shutil.copyfile(fallback, output_path)
            return

    raise RuntimeError("Could not build or locate a dummy Windows .exe for installer tests")


def _sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(sys.platform == "win32", "install.ps1 tests require Windows")
class TestInstallPs1(unittest.TestCase):
    """End-to-end offline verification suite for REQ-003 (install.ps1)."""

    powershell_bin: str = ""
    _tmpdir: tempfile.TemporaryDirectory[str] | None = None
    dummy_exe: Path = Path()

    @classmethod
    def setUpClass(cls) -> None:
        cls.powershell_bin = _find_powershell()
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.dummy_exe = Path(cls._tmpdir.name) / "dummy_arc.exe"
        _build_dummy_exe(cls.dummy_exe)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()

    def _create_fixture_archive(
        self,
        directory: Path,
        archive_name: str = ARCHIVE_NAME,
        include_sidecar: bool = True,
        include_licenses: bool = True,
    ) -> Path:
        archive_path = directory / archive_name
        exe_bytes = self.dummy_exe.read_bytes()
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("arc.exe", exe_bytes)
            if include_sidecar:
                zf.writestr("arc-decision-ui-host.exe", exe_bytes)
            if include_licenses:
                zf.writestr("LICENSE-MIT", "MIT License\nCopyright (c) 2026 Arc Contributors\n")
                zf.writestr("LICENSE-APACHE", "Apache License\nVersion 2.0, January 2004\n")
            zf.writestr("README.md", "# Arc v1.0.0\n")
        return archive_path

    def _run_install_ps1(
        self,
        args: list[str],
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not INSTALL_PS1_PATH.is_file():
            raise AssertionError(
                f"Expected Windows installer at {INSTALL_PS1_PATH}, but file does not exist"
            )
        env = os.environ.copy()
        for key in ("ARC_VERSION", "ARC_INSTALL_DIR", "ARC_RELEASE_BASE_URL"):
            env.pop(key, None)
        if env_overrides:
            env.update(env_overrides)

        cmd = [
            self.powershell_bin,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALL_PS1_PATH),
            *args,
        ]
        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_script_exists_and_help_flag_prints_usage_and_exits_zero(self) -> None:
        """CP-01 (AC-003.1, AC-003.3): install.ps1 exists and -Help prints usage and exits 0."""
        self.assertTrue(
            INSTALL_PS1_PATH.is_file(),
            f"install.ps1 must exist at {INSTALL_PS1_PATH}",
        )
        proc = self._run_install_ps1(["-Help"])
        self.assertEqual(
            proc.returncode,
            0,
            f"install.ps1 -Help failed with code {proc.returncode}: {proc.stderr}",
        )
        combined = proc.stdout + "\n" + proc.stderr
        for token in (
            "-Version",
            "-InstallDir",
            "-ArchivePath",
            "-ChecksumPath",
            "-NoModifyPath",
        ):
            self.assertIn(
                token,
                combined,
                f"install.ps1 -Help output must document parameter '{token}'",
            )

    def test_offline_install_extracts_sibling_binaries_and_licenses_and_prints_license_notice(
        self,
    ) -> None:
        """CP-02 (AC-003.1, AC-003.4, AC-003.5): valid offline install extracts binaries side-by-side and shows MIT OR Apache-2.0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ]
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"Expected exit code 0 for valid offline install, got {proc.returncode}.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )

            arc_exe = install_dir / "arc.exe"
            sidecar_exe = install_dir / "arc-decision-ui-host.exe"
            self.assertTrue(arc_exe.is_file(), "arc.exe must be installed in InstallDir")
            self.assertTrue(
                sidecar_exe.is_file(),
                "arc-decision-ui-host.exe must be installed side-by-side in InstallDir",
            )
            self.assertEqual(
                arc_exe.parent.resolve(),
                sidecar_exe.parent.resolve(),
                "arc.exe and arc-decision-ui-host.exe must reside in the exact same directory",
            )

            license_mit = (install_dir / "LICENSE-MIT").is_file() or (
                install_dir.parent / "LICENSE-MIT"
            ).is_file()
            license_apache = (install_dir / "LICENSE-APACHE").is_file() or (
                install_dir.parent / "LICENSE-APACHE"
            ).is_file()
            self.assertTrue(license_mit, "LICENSE-MIT must be copied during install")
            self.assertTrue(license_apache, "LICENSE-APACHE must be copied during install")

            self.assertIn(
                "MIT OR Apache-2.0",
                proc.stdout,
                "install.ps1 must print the 'MIT OR Apache-2.0' license notice to stdout",
            )

    def test_checksum_mismatch_aborts_nonzero_before_extracting_binaries(self) -> None:
        """CP-03 (AC-003.2, AC-003.5): corrupted SHA256SUMS aborts non-zero without installing binaries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            checksum_path = tmp / "SHA256SUMS"
            bad_digest = "0" * 64
            checksum_path.write_text(
                f"{bad_digest}  {ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.ps1 must exit with non-zero code when SHA-256 checksum mismatches",
            )
            self.assertFalse(
                (install_dir / "arc.exe").exists(),
                "arc.exe must not be extracted when checksum verification fails",
            )
            self.assertFalse(
                (install_dir / "arc-decision-ui-host.exe").exists(),
                "arc-decision-ui-host.exe must not be extracted when checksum verification fails",
            )

    def test_missing_archive_entry_in_sha256sums_aborts_nonzero(self) -> None:
        """CP-04 (AC-003.2): SHA256SUMS missing an entry for the target archive aborts non-zero."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  arc-v1.0.0-x86_64-unknown-linux-gnu.tar.gz\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.ps1 must exit non-zero when SHA256SUMS has no matching archive entry",
            )
            self.assertFalse(
                (install_dir / "arc.exe").exists(),
                "arc.exe must not be extracted when SHA256SUMS entry is missing",
            )

    def test_environment_variable_fallbacks_and_default_home_install_dir(self) -> None:
        """CP-05 (AC-003.1, AC-003.3): ARC_VERSION, ARC_INSTALL_DIR, and default $HOME\\.arc\\bin work offline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {ARCHIVE_NAME}\n",
                encoding="utf-8",
            )

            # 1) Test ARC_VERSION (with leading 'v') and ARC_INSTALL_DIR environment variable fallbacks
            env_install_dir = tmp / "env_bin"
            proc_env = self._run_install_ps1(
                [
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-NoModifyPath",
                ],
                env_overrides={
                    "ARC_VERSION": "v1.0.0",
                    "ARC_INSTALL_DIR": str(env_install_dir),
                },
            )
            self.assertEqual(
                proc_env.returncode,
                0,
                f"Expected exit 0 with ARC_VERSION/ARC_INSTALL_DIR env vars, got {proc_env.returncode}: {proc_env.stderr}",
            )
            self.assertTrue((env_install_dir / "arc.exe").is_file())
            self.assertTrue((env_install_dir / "arc-decision-ui-host.exe").is_file())

            # 2) Test default $HOME\.arc\bin when -InstallDir and ARC_INSTALL_DIR are omitted
            fake_home = tmp / "fake_home"
            fake_home.mkdir()
            proc_home = self._run_install_ps1(
                [
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-NoModifyPath",
                ],
                env_overrides={
                    "HOME": str(fake_home),
                    "USERPROFILE": str(fake_home),
                },
            )
            self.assertEqual(
                proc_home.returncode,
                0,
                f"Expected exit 0 with default $HOME\\.arc\\bin destination, got {proc_home.returncode}: {proc_home.stderr}",
            )
            default_bin = fake_home / ".arc" / "bin"
            self.assertTrue(
                (default_bin / "arc.exe").is_file(),
                f"Expected arc.exe in default install directory {default_bin}",
            )
            self.assertTrue(
                (default_bin / "arc-decision-ui-host.exe").is_file(),
                f"Expected arc-decision-ui-host.exe in default install directory {default_bin}",
            )

    def test_missing_sidecar_in_archive_fails_verification_with_nonzero_exit(self) -> None:
        """CP-06 (AC-003.4): archive missing arc-decision-ui-host.exe fails sibling verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp, include_sidecar=False)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.ps1 must fail with non-zero exit code if arc-decision-ui-host.exe is missing",
            )

    def test_path_detection_and_no_modify_path_guidance(self) -> None:
        """CP-07 (AC-003.4, AC-003.3): PATH inspection prints guidance when InstallDir is not on PATH and -NoModifyPath is passed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "unlisted_bin"

            proc_not_in_path = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ]
            )
            self.assertEqual(proc_not_in_path.returncode, 0)
            combined_out = proc_not_in_path.stdout + "\n" + proc_not_in_path.stderr
            self.assertIn(
                "PATH",
                combined_out.upper(),
                "install.ps1 must print PATH guidance when InstallDir is not in PATH and -NoModifyPath is set",
            )

            # Now test when InstallDir is already present in process PATH
            existing_path = os.environ.get("PATH", "")
            proc_in_path = self._run_install_ps1(
                [
                    "-Version",
                    "1.0.0",
                    "-ArchivePath",
                    str(archive_path),
                    "-ChecksumPath",
                    str(checksum_path),
                    "-InstallDir",
                    str(install_dir),
                    "-NoModifyPath",
                ],
                env_overrides={"PATH": f"{install_dir};{existing_path}"},
            )
            self.assertEqual(proc_in_path.returncode, 0)


if __name__ == "__main__":
    unittest.main()
