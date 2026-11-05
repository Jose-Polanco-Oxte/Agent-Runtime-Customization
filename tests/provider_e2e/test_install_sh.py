import hashlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH_PATH = REPO_ROOT / "install.sh"
DEFAULT_TARGET = "x86_64-unknown-linux-gnu"
DEFAULT_ARCHIVE_NAME = f"arc-v1.0.0-{DEFAULT_TARGET}.tar.gz"


def _find_posix_sh() -> tuple[str, list[str]]:
    """Resolve a POSIX sh executable and any extra PATH directories needed on Windows."""
    if os.name == "nt":
        git_root = Path(r"C:\Program Files\Git")
        git_sh = git_root / "bin" / "sh.exe"
        git_usr_bin = git_root / "usr" / "bin"
        git_bin = git_root / "bin"
        if git_sh.is_file():
            extra_paths = [str(p) for p in (git_usr_bin, git_bin) if p.is_dir()]
            return str(git_sh), extra_paths

    resolved = shutil.which("sh") or shutil.which("bash")
    if resolved:
        return resolved, []
    raise RuntimeError("No POSIX sh or bash executable found on host")


def _sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _add_tar_bytes(tf: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    tf.addfile(info, io.BytesIO(data))


class TestInstallSh(unittest.TestCase):
    """End-to-end offline verification suite for REQ-004 (install.sh)."""

    sh_bin: str = ""
    extra_path_dirs: list[str] = []

    @classmethod
    def setUpClass(cls) -> None:
        cls.sh_bin, cls.extra_path_dirs = _find_posix_sh()

    def _create_fixture_archive(
        self,
        directory: Path,
        archive_name: str = DEFAULT_ARCHIVE_NAME,
        include_sidecar: bool = True,
        include_licenses: bool = True,
    ) -> Path:
        archive_path = directory / archive_name
        arc_script = (
            b"#!/bin/sh\n"
            b'if [ "$1" = "--version" ]; then\n'
            b'  echo "arc 1.0.0"\n'
            b"  exit 0\n"
            b"fi\n"
            b"exit 0\n"
        )
        sidecar_script = b"#!/bin/sh\nexit 0\n"

        with tarfile.open(archive_path, "w:gz") as tf:
            _add_tar_bytes(tf, "arc", arc_script, mode=0o755)
            if include_sidecar:
                _add_tar_bytes(tf, "arc-decision-ui-host", sidecar_script, mode=0o755)
            if include_licenses:
                _add_tar_bytes(
                    tf,
                    "LICENSE-MIT",
                    b"MIT License\nCopyright (c) 2026 Arc Contributors\n",
                    mode=0o644,
                )
                _add_tar_bytes(
                    tf,
                    "LICENSE-APACHE",
                    b"Apache License\nVersion 2.0, January 2004\n",
                    mode=0o644,
                )
            _add_tar_bytes(tf, "README.md", b"# Arc v1.0.0\n", mode=0o644)

        return archive_path

    def _build_env(
        self,
        env_overrides: dict[str, str] | None = None,
        prepend_path_dirs: list[Path] | None = None,
    ) -> dict[str, str]:
        env = os.environ.copy()
        for key in ("ARC_VERSION", "ARC_INSTALL_DIR", "ARC_RELEASE_BASE_URL"):
            env.pop(key, None)

        path_parts: list[str] = []
        if prepend_path_dirs:
            path_parts.extend(str(p) for p in prepend_path_dirs)
        if self.extra_path_dirs:
            path_parts.extend(self.extra_path_dirs)
        existing_path = env.get("PATH", "")
        if existing_path:
            path_parts.append(existing_path)
        env["PATH"] = os.pathsep.join(path_parts)

        if env_overrides:
            env.update(env_overrides)
        return env

    def _run_install_sh(
        self,
        args: list[str],
        env_overrides: dict[str, str] | None = None,
        prepend_path_dirs: list[Path] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not INSTALL_SH_PATH.is_file():
            raise AssertionError(
                f"Expected Unix installer at {INSTALL_SH_PATH}, but file does not exist"
            )
        env = self._build_env(
            env_overrides=env_overrides,
            prepend_path_dirs=prepend_path_dirs,
        )
        cmd = [self.sh_bin, INSTALL_SH_PATH.as_posix(), *args]
        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_syntax_validation_and_help_flag_exits_zero(self) -> None:
        """CP-01 (AC-004.1, AC-004.3, AC-004.5): sh -n install.sh passes and --help/-h prints usage and exits 0."""
        self.assertTrue(
            INSTALL_SH_PATH.is_file(),
            f"install.sh must exist at {INSTALL_SH_PATH}",
        )
        syntax_proc = subprocess.run(
            [self.sh_bin, "-n", INSTALL_SH_PATH.as_posix()],
            cwd=str(REPO_ROOT),
            env=self._build_env(),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            syntax_proc.returncode,
            0,
            f"sh -n install.sh failed with syntax error:\n{syntax_proc.stderr}",
        )

        for flag in ("--help", "-h"):
            proc = self._run_install_sh([flag])
            self.assertEqual(
                proc.returncode,
                0,
                f"install.sh {flag} failed with code {proc.returncode}: {proc.stderr}",
            )
            combined = proc.stdout + "\n" + proc.stderr
            for token in (
                "--version",
                "--install-dir",
                "--archive",
                "--checksums",
                "--target",
                "--no-modify-path",
            ):
                self.assertIn(
                    token,
                    combined,
                    f"install.sh {flag} output must document option '{token}'",
                )

    def test_offline_install_extracts_sibling_binaries_permissions_licenses_and_runs_version(
        self,
    ) -> None:
        """CP-02 (AC-004.1, AC-004.3, AC-004.4, AC-004.5): offline install extracts binaries side-by-side (0755), copies licenses, runs arc --version, and prints MIT OR Apache-2.0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {DEFAULT_ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_sh(
                [
                    "--version",
                    "1.0.0",
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--install-dir",
                    install_dir.as_posix(),
                    "--no-modify-path",
                ]
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"Expected exit code 0 for valid offline install, got {proc.returncode}.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )

            arc_bin = install_dir / "arc"
            sidecar_bin = install_dir / "arc-decision-ui-host"
            self.assertTrue(arc_bin.is_file(), "arc must be installed in InstallDir")
            self.assertTrue(
                sidecar_bin.is_file(),
                "arc-decision-ui-host must be installed side-by-side in InstallDir",
            )
            self.assertEqual(
                arc_bin.parent.resolve(),
                sidecar_bin.parent.resolve(),
                "arc and arc-decision-ui-host must reside in the exact same directory",
            )

            exec_check = subprocess.run(
                [
                    self.sh_bin,
                    "-c",
                    'test -x "$1" && test -x "$2"',
                    "--",
                    arc_bin.as_posix(),
                    sidecar_bin.as_posix(),
                ],
                env=self._build_env(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                exec_check.returncode,
                0,
                "Both arc and arc-decision-ui-host must be executable",
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(arc_bin.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(sidecar_bin.stat().st_mode), 0o755)

            license_mit = (install_dir / "LICENSE-MIT").is_file() or (
                install_dir.parent / "LICENSE-MIT"
            ).is_file()
            license_apache = (install_dir / "LICENSE-APACHE").is_file() or (
                install_dir.parent / "LICENSE-APACHE"
            ).is_file()
            self.assertTrue(license_mit, "LICENSE-MIT must be installed")
            self.assertTrue(license_apache, "LICENSE-APACHE must be installed")

            self.assertIn(
                "MIT OR Apache-2.0",
                proc.stdout,
                "install.sh must print the 'MIT OR Apache-2.0' license notice to stdout",
            )
            self.assertIn(
                "arc 1.0.0",
                proc.stdout,
                "install.sh must execute '$INSTALL_DIR/arc --version' and show version output",
            )

    def test_host_os_and_arch_autodetection_and_unsupported_platform_rejection(self) -> None:
        """CP-03 (AC-004.1, AC-004.3): auto-detects Linux/Darwin and x86_64/arm64/aarch64 via uname and rejects unsupported platforms."""
        matrix = [
            ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
            ("Darwin", "arm64", "aarch64-apple-darwin"),
            ("Darwin", "aarch64", "aarch64-apple-darwin"),
            ("Darwin", "x86_64", "x86_64-apple-darwin"),
        ]
        for os_name, arch_name, expected_target in matrix:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                mock_bin = tmp / "mock_bin"
                mock_bin.mkdir()
                mock_uname = mock_bin / "uname"
                mock_uname.write_bytes(
                    b"#!/bin/sh\n"
                    b'case "$1" in\n'
                    b'  -s) echo "' + os_name.encode("ascii") + b'" ;;\n'
                    b'  -m) echo "' + arch_name.encode("ascii") + b'" ;;\n'
                    b'  *) echo "' + os_name.encode("ascii") + b'" ;;\n'
                    b"esac\n"
                )
                mock_uname.chmod(0o755)

                archive_name = f"arc-v1.0.0-{expected_target}.tar.gz"
                archive_path = self._create_fixture_archive(tmp, archive_name=archive_name)
                digest = _sha256_hex(archive_path)
                checksum_path = tmp / "SHA256SUMS"
                checksum_path.write_text(f"{digest}  {archive_name}\n", encoding="utf-8")
                install_dir = tmp / "bin"

                proc = self._run_install_sh(
                    [
                        "--version",
                        "1.0.0",
                        "--archive",
                        archive_path.as_posix(),
                        "--checksums",
                        checksum_path.as_posix(),
                        "--install-dir",
                        install_dir.as_posix(),
                        "--no-modify-path",
                    ],
                    prepend_path_dirs=[mock_bin],
                )
                self.assertEqual(
                    proc.returncode,
                    0,
                    f"Auto-detection failed for {os_name}/{arch_name} -> {expected_target}: {proc.stderr}",
                )
                self.assertTrue((install_dir / "arc").is_file())
                self.assertTrue((install_dir / "arc-decision-ui-host").is_file())

        # Unsupported OS/arch rejection
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            mock_bin = tmp / "mock_bin"
            mock_bin.mkdir()
            mock_uname = mock_bin / "uname"
            mock_uname.write_bytes(
                b"#!/bin/sh\n"
                b'case "$1" in\n'
                b'  -s) echo "FreeBSD" ;;\n'
                b'  -m) echo "riscv64" ;;\n'
                b'  *) echo "FreeBSD" ;;\n'
                b"esac\n"
            )
            mock_uname.chmod(0o755)

            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(f"{digest}  {DEFAULT_ARCHIVE_NAME}\n", encoding="utf-8")
            install_dir = tmp / "bin"

            proc_bad = self._run_install_sh(
                [
                    "--version",
                    "1.0.0",
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--install-dir",
                    install_dir.as_posix(),
                    "--no-modify-path",
                ],
                prepend_path_dirs=[mock_bin],
            )
            self.assertNotEqual(
                proc_bad.returncode,
                0,
                "install.sh must reject unsupported OS/architecture with a non-zero exit code",
            )

    def test_checksum_mismatch_aborts_nonzero_before_installing_binaries(self) -> None:
        """CP-04 (AC-004.2, AC-004.5): corrupted SHA256SUMS exits non-zero before installing binaries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            checksum_path = tmp / "SHA256SUMS"
            bad_digest = "0" * 64
            checksum_path.write_text(
                f"{bad_digest}  {DEFAULT_ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_sh(
                [
                    "--version",
                    "1.0.0",
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--install-dir",
                    install_dir.as_posix(),
                    "--no-modify-path",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.sh must exit with non-zero code when SHA-256 checksum mismatches",
            )
            self.assertFalse(
                (install_dir / "arc").exists(),
                "arc must not be installed when checksum verification fails",
            )
            self.assertFalse(
                (install_dir / "arc-decision-ui-host").exists(),
                "arc-decision-ui-host must not be installed when checksum verification fails",
            )

    def test_missing_archive_entry_in_sha256sums_aborts_nonzero(self) -> None:
        """CP-05 (AC-004.2): SHA256SUMS missing an entry for the target archive exits non-zero."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  arc-v1.0.0-aarch64-apple-darwin.tar.gz\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_sh(
                [
                    "--version",
                    "1.0.0",
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--install-dir",
                    install_dir.as_posix(),
                    "--no-modify-path",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.sh must exit non-zero when SHA256SUMS has no matching archive entry",
            )
            self.assertFalse(
                (install_dir / "arc").exists(),
                "arc must not be installed when SHA256SUMS entry is missing",
            )

    def test_missing_sidecar_in_archive_fails_verification_with_nonzero_exit(self) -> None:
        """CP-06 (AC-004.4, AC-004.5): archive missing arc-decision-ui-host fails sibling verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp, include_sidecar=False)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {DEFAULT_ARCHIVE_NAME}\n",
                encoding="utf-8",
            )
            install_dir = tmp / "bin"

            proc = self._run_install_sh(
                [
                    "--version",
                    "1.0.0",
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--install-dir",
                    install_dir.as_posix(),
                    "--no-modify-path",
                ]
            )
            self.assertNotEqual(
                proc.returncode,
                0,
                "install.sh must fail with non-zero exit code if arc-decision-ui-host is missing",
            )

    def test_environment_variable_fallbacks_and_path_guidance(self) -> None:
        """CP-07 (AC-004.1, AC-004.3, AC-004.4): ARC_VERSION/ARC_INSTALL_DIR/HOME fallbacks and PATH guidance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = self._create_fixture_archive(tmp)
            digest = _sha256_hex(archive_path)
            checksum_path = tmp / "SHA256SUMS"
            checksum_path.write_text(
                f"{digest}  {DEFAULT_ARCHIVE_NAME}\n",
                encoding="utf-8",
            )

            # 1) Test ARC_VERSION (with leading 'v') and ARC_INSTALL_DIR when not on PATH
            env_install_dir = tmp / "env_bin"
            proc_env = self._run_install_sh(
                [
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--no-modify-path",
                ],
                env_overrides={
                    "ARC_VERSION": "v1.0.0",
                    "ARC_INSTALL_DIR": env_install_dir.as_posix(),
                },
            )
            self.assertEqual(
                proc_env.returncode,
                0,
                f"Expected exit 0 with ARC_VERSION/ARC_INSTALL_DIR env vars, got {proc_env.returncode}: {proc_env.stderr}",
            )
            self.assertTrue((env_install_dir / "arc").is_file())
            self.assertTrue((env_install_dir / "arc-decision-ui-host").is_file())
            combined_out = proc_env.stdout + "\n" + proc_env.stderr
            self.assertIn(
                "PATH",
                combined_out,
                "install.sh must print PATH instructions when InstallDir is not in PATH",
            )

            # 2) Test default $HOME/.arc/bin and when InstallDir is already on PATH
            fake_home = tmp / "fake_home"
            fake_home.mkdir()
            default_bin = fake_home / ".arc" / "bin"
            proc_home = self._run_install_sh(
                [
                    "--target",
                    DEFAULT_TARGET,
                    "--archive",
                    archive_path.as_posix(),
                    "--checksums",
                    checksum_path.as_posix(),
                    "--no-modify-path",
                ],
                env_overrides={
                    "HOME": fake_home.as_posix(),
                },
                prepend_path_dirs=[default_bin],
            )
            self.assertEqual(
                proc_home.returncode,
                0,
                f"Expected exit 0 with default $HOME/.arc/bin destination, got {proc_home.returncode}: {proc_home.stderr}",
            )
            self.assertTrue(
                (default_bin / "arc").is_file(),
                f"Expected arc in default install directory {default_bin}",
            )
            self.assertTrue(
                (default_bin / "arc-decision-ui-host").is_file(),
                f"Expected arc-decision-ui-host in default install directory {default_bin}",
            )


if __name__ == "__main__":
    unittest.main()
