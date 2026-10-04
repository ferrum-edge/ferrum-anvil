"""Hosted tests of the actual release checker; requires gcc and squashfs-tools.

Fixtures are built only on GitHub-hosted Linux runners. The input runtime is a
native executable that writes a sentinel on *any* invocation, including an
offset/extraction request. SquashFS payloads are real compressed filesystems.
"""

import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECKER = ROOT / "scripts/release-check.sh"


def require_github_hosted():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError(
            "release checker fixtures require GITHUB_ACTIONS=true and "
            "RUNNER_ENVIRONMENT=github-hosted"
        )


def hosted_subprocess(command, **kwargs):
    require_github_hosted()
    return subprocess.run(command, **kwargs)


def run(command, **kwargs):
    return hosted_subprocess(
        command, check=True, capture_output=True, text=True, timeout=30, **kwargs
    )


def squashfs_payload(appdir, squashfs):
    run([
        "mksquashfs", str(appdir), str(squashfs), "-noappend", "-no-xattrs",
        "-all-root", "-processors", "1", "-comp", "gzip",
    ])
    return squashfs.read_bytes()


def data_runtime(elf_class=2, endian="<", machine=62, section_last=False):
    """ELF metadata layouts supported by the official Type 2 offset algorithm.

    Include a large non-file-backed BSS and a decoy SquashFS magic, so neither
    memory size nor a search for magic bytes can substitute for the ELF boundary.
    These architecture variants are inspected as data, never launched.
    """
    elf64 = elf_class == 2
    ehsize, phsize, shsize = (64, 56, 64) if elf64 else (52, 32, 40)
    shoff = 128 if section_last else 384
    section_start = 384 if section_last else 256
    offset = max(shoff + shsize * 3, section_start + 64)
    ident = bytearray(b"\x7fELF" + bytes(12))
    ident[4:7] = bytes((elf_class, 1 if endian == "<" else 2, 1))
    ident[8:11] = b"AI\x02"
    header = struct.pack(
        endian + ("HHIQQQIHHHHHH" if elf64 else "HHIIIIIHHHHHH"),
        2, machine, 1, 0, ehsize, shoff, 0, ehsize, phsize, 1, shsize, 3, 2,
    )
    program_fields = (
        (1, 5, 0, 0, 0, offset, offset, 4096) if elf64
        else (1, 0, 0, 0, offset, offset, 5, 4096)
    )
    program = struct.pack(endian + ("IIQQQQQQ" if elf64 else "IIIIIIII"), *program_fields)
    section_format = endian + ("IIQQQQIIQQ" if elf64 else "IIIIIIIIII")
    sections = (
        bytes(shsize)
        + struct.pack(section_format, 0, 8, 0, 0, 192, 65536, 0, 0, 1, 0)
        + struct.pack(section_format, 0, 3, 0, 0, section_start, 64, 0, 0, 1, 0)
    )
    runtime = bytearray(offset)
    runtime[:ehsize] = ident + header
    runtime[ehsize:ehsize + phsize] = program
    runtime[shoff:shoff + len(sections)] = sections
    runtime[section_start:section_start + 16] = b"\0.shstrtab\0data\0"
    runtime[section_start + 16:section_start + 20] = b"hsqs"
    return bytes(runtime)


class ReleaseCheckAppImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        require_github_hosted()
        for tool in ("gcc", "mksquashfs", "unsquashfs", "python3", "curl"):
            if shutil.which(tool) is None:
                raise RuntimeError(f"hosted fixture dependency missing: {tool}")
        cls.fixture_temp = tempfile.TemporaryDirectory(prefix="release-check-fixtures-")
        cls.addClassCleanup(cls.fixture_temp.cleanup)
        cls.fixture_root = Path(cls.fixture_temp.name)
        runtime = cls.fixture_root / "runtime"
        desktop = cls.fixture_root / "desktop"
        run(["gcc", "-O0", "-o", str(runtime), str(FIXTURES / "appimage-runtime.c")])
        run(["gcc", "-O0", "-o", str(desktop), str(FIXTURES / "appimage-desktop.c")])
        # Reserved e_ident bytes carry Type 2 magic without changing executable code.
        cls.native_runtime = bytearray(runtime.read_bytes())
        cls.native_runtime[8:11] = b"AI\x02"
        cls.payloads = {}
        for kind in (
            "clean", "forbidden", "forbidden-newline-file", "forbidden-newline-dir",
            "clean-newline", "foreign", "no-executables", "no-apprun",
        ):
            appdir = cls.fixture_root / kind
            (appdir / "usr/bin").mkdir(parents=True)
            if kind != "no-apprun":
                apprun = appdir / "AppRun"
                apprun.write_text(
                    '#!/bin/sh\n'
                    'printf "%s\\n" "$0" > "$RELEASE_CHECK_APPRUN_SENTINEL"\n'
                    'if [ -n "${RELEASE_CHECK_SERVE_WEBDRIVER:-}" ]; then\n'
                    '  exec python3 -I -m http.server "$TAURI_WEBDRIVER_PORT" '
                    '--bind 127.0.0.1\n'
                    'fi\n'
                    'exec "$(dirname "$0")/usr/bin/anvil-desktop"\n'
                )
                apprun.chmod(0o755)
            executable = appdir / "usr/bin/anvil-desktop"
            if kind == "foreign":
                executable.write_bytes(b"\x7fELFforeign executable without Anvil markers")
            elif kind == "no-executables":
                executable.write_text("not an executable image")
            else:
                shutil.copyfile(desktop, executable)
            executable.chmod(0o755)
            libraries = {
                "forbidden": "usr/lib/libhooks.so",
                "forbidden-newline-file": "usr/lib/libhooks\n.so",
                "forbidden-newline-dir": "usr/\n/libhooks.so",
                "clean-newline": "usr/lib/clean\n.so",
            }
            if kind in libraries:
                library = appdir / libraries[kind]
                library.parent.mkdir(parents=True)
                marker = b"ANVIL_DATA_DIR" if kind == "clean-newline" else b"/wdio/eval"
                library.write_bytes(b"\x7fELF\0" + marker + b"\0")
            squashfs = cls.fixture_root / f"{kind}.squashfs"
            cls.payloads[kind] = squashfs_payload(appdir, squashfs)

    def setUp(self):
        self.case_temp = tempfile.TemporaryDirectory(prefix="release-check-case-")
        self.addCleanup(self.case_temp.cleanup)
        self.case_root = Path(self.case_temp.name)
        self.runtime_sentinel = self.case_root / "runtime-ran"
        self.apprun_sentinel = self.case_root / "apprun-ran"
        self.desktop_sentinel = self.case_root / "desktop-ran"
        self.env = {
            **os.environ,
            "RELEASE_CHECK_RUNTIME_SENTINEL": str(self.runtime_sentinel),
            "RELEASE_CHECK_APPRUN_SENTINEL": str(self.apprun_sentinel),
            "RELEASE_CHECK_DESKTOP_SENTINEL": str(self.desktop_sentinel),
        }
        for key in ("RELEASE_CHECK_CREATE_PROFILE", "RELEASE_CHECK_EXIT_EARLY",
                    "RELEASE_CHECK_SERVE_WEBDRIVER"):
            self.env.pop(key, None)

    def image(self, runtime=None, payload="clean", mode=0o755):
        image = self.case_root / "untrusted image.AppImage"
        prefix = self.native_runtime if runtime is None else runtime
        image.write_bytes(prefix + self.payloads[payload])
        image.chmod(mode)
        return image

    def check(self, image, expected, *options, env=None, cwd=None):
        report = self.case_root / "report.json"
        report.unlink(missing_ok=True)
        image_path = image if image.is_absolute() else (cwd or self.case_root) / image
        before = image_path.read_bytes(), stat.S_IMODE(image_path.stat().st_mode)
        result = hosted_subprocess(
            ["/bin/bash", str(CHECKER), "--no-graph", "--report", str(report),
             *options, str(image)],
            env=self.env if env is None else env,
            cwd=self.case_root if cwd is None else cwd,
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout + result.stderr
        # Check this first so an execution regression is explicit even if exit/status fails.
        self.assertFalse(self.runtime_sentinel.exists(), output)
        self.assertEqual(before, (image_path.read_bytes(), stat.S_IMODE(image_path.stat().st_mode)))
        self.assertEqual(result.returncode, expected, output)
        evidence = json.loads(report.read_text())
        self.assertEqual(evidence["graph"], "skipped")
        self.assertEqual(evidence["result"], {0: "pass", 1: "fail", 2: "error"}[expected])
        return evidence, output

    def assert_no_payload_execution(self):
        self.assertFalse(self.apprun_sentinel.exists())
        self.assertFalse(self.desktop_sentinel.exists())

    def test_native_malicious_runtime_is_never_invoked(self):
        evidence, _ = self.check(self.image(), 0)
        self.assertEqual(evidence["artifacts"][0]["executables"], 1)
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "skipped")
        self.assert_no_payload_execution()

    def test_sentinel_fixture_positive_control(self):
        # Hosted-only control: prove the native fixture would record either call.
        image = self.image()
        for option in ("--appimage-offset", "--appimage-extract"):
            control = self.case_root / option.removeprefix("--")
            run([str(image), option], env={
                **self.env, "RELEASE_CHECK_RUNTIME_SENTINEL": str(control),
            })
            self.assertIn("runtime executed", control.read_text())
        self.check(image, 0)
        self.assert_no_payload_execution()

    def test_input_is_not_made_executable(self):
        self.check(self.image(mode=0o644), 0)
        self.assert_no_payload_execution()

    def test_type2_architectures_and_both_elf_end_layouts(self):
        for elf_class, endian, machine in (
            (1, "<", 3), (1, "<", 40), (2, "<", 62), (2, "<", 183),
            (1, ">", 20), (2, ">", 21),
        ):
            for section_last in (False, True):
                with self.subTest(elf_class=elf_class, endian=endian, machine=machine,
                                  section_last=section_last):
                    self.check(self.image(data_runtime(
                        elf_class, endian, machine, section_last
                    )), 0)
                    self.assert_no_payload_execution()

    def test_forbidden_marker_in_extracted_library_is_rejected(self):
        evidence, output = self.check(self.image(payload="forbidden"), 1)
        self.assertIn("libhooks.so: contains test-only strings", output)
        self.assertEqual(evidence["artifacts"][0]["executables"], 2)
        self.assertIn("/wdio/eval", evidence["artifacts"][0]["hits"])
        self.assert_no_payload_execution()

    def test_newline_filenames_and_directories_cannot_hide_hook_images(self):
        for payload in ("forbidden-newline-file", "forbidden-newline-dir"):
            with self.subTest(payload=payload):
                evidence, output = self.check(self.image(payload=payload), 1)
                self.assertIn("contains test-only strings", output)
                self.assertEqual(evidence["artifacts"][0]["executables"], 2)
                self.assertIn("/wdio/eval", evidence["artifacts"][0]["hits"])
                self.assert_no_payload_execution()

    def test_clean_newline_filename_is_scanned(self):
        evidence, _ = self.check(self.image(payload="clean-newline"), 0)
        self.assertEqual(evidence["artifacts"][0]["executables"], 2)
        self.assert_no_payload_execution()

    def test_newline_directory_cannot_redirect_a_scan_to_a_host_path(self):
        host = self.case_root / "host-hooks.so"
        host.write_bytes(b"\x7fELF\0ANVIL_DATA_DIR\0/wdio/eval\0")
        before = host.read_bytes()
        # Positive control: this outside file really is an image with hook strings.
        evidence, _ = self.check(host, 1)
        self.assertIn("/wdio/eval", evidence["artifacts"][0]["hits"])
        appdir = self.case_root / "newline-host-path"
        shutil.copytree(self.fixture_root / "clean", appdir)
        # A newline-delimited find reader would turn the suffix into /tmp/...
        # and scan the outside hook image instead of this clean inside image.
        inside = appdir / "\n" / str(host).lstrip("/")
        inside.parent.mkdir(parents=True)
        inside.write_bytes(b"\x7fELF\0ANVIL_DATA_DIR\0")
        payload = squashfs_payload(appdir, self.case_root / "newline-host.squashfs")
        image = self.image()
        image.write_bytes(self.native_runtime + payload)
        evidence, _ = self.check(image, 0)
        self.assertEqual(evidence["artifacts"][0]["executables"], 2)
        self.assertEqual(host.read_bytes(), before)
        self.assert_no_payload_execution()

    def test_newline_artifact_paths_and_option_like_names_are_preserved(self):
        directory = self.case_root / "-images\n"
        directory.mkdir()
        image = self.image().rename(directory / '-untrusted"\\\t\nimage.AppImage')
        for argument, cwd in (
            (image, self.case_root),
            (image.relative_to(self.case_root), self.case_root),
            (Path(image.name), directory),
        ):
            with self.subTest(argument=str(argument)):
                evidence, _ = self.check(argument, 0, "--", cwd=cwd)
                self.assertEqual(evidence["artifacts"][0]["artifact"], str(argument))
                self.assertEqual(evidence["artifacts"][0]["executables"], 1)
                self.assert_no_payload_execution()

    def test_extracted_symlinks_must_stay_in_the_appimage_tree(self):
        host = self.case_root / "outside.so"
        host.write_bytes((self.fixture_root / "desktop").read_bytes() + b"\0/wdio/eval\0")
        host.chmod(0o755)
        before = host.read_bytes()
        for kind in ("apprun", "file", "directory", "relative"):
            with self.subTest(kind=kind):
                appdir = self.case_root / f"symlink-{kind}"
                shutil.copytree(self.fixture_root / "clean", appdir)
                if kind == "apprun":
                    (appdir / "AppRun").unlink()
                    (appdir / "AppRun").symlink_to(host)
                elif kind == "directory":
                    (appdir / "outside").symlink_to(self.case_root, target_is_directory=True)
                else:
                    target = host if kind == "file" else "../../../../outside.so"
                    (appdir / "usr/bin/outside.so").symlink_to(target)
                payload = squashfs_payload(appdir, self.case_root / f"symlink-{kind}.squashfs")
                image = self.image()
                image.write_bytes(self.native_runtime + payload)
                for options in ((), ("--runtime-probe", "--probe-seconds", "1")):
                    _, output = self.check(image, 2, *options)
                    self.assertIn("symlink escapes the extraction directory", output)
                    self.assertEqual(host.read_bytes(), before)
                    self.assert_no_payload_execution()

    def test_contained_apprun_symlink_remains_supported(self):
        appdir = self.case_root / "contained-link"
        shutil.copytree(self.fixture_root / "clean", appdir)
        (appdir / "AppRun").rename(appdir / "usr/bin/launcher")
        (appdir / "AppRun").symlink_to("usr/bin/launcher")
        payload = squashfs_payload(appdir, self.case_root / "contained-link.squashfs")
        image = self.image()
        image.write_bytes(self.native_runtime + payload)
        evidence, _ = self.check(image, 0)
        self.assertEqual(evidence["artifacts"][0]["executables"], 1)
        self.assert_no_payload_execution()

    def test_foreign_payload_and_empty_scan_fail_closed(self):
        for payload, message in (
            ("foreign", "no Anvil marker string"),
            ("no-executables", "no executable images found"),
            ("no-apprun", "AppImage has no AppRun"),
        ):
            with self.subTest(payload=payload):
                _, output = self.check(self.image(payload=payload), 2)
                self.assertIn(message, output)
                self.assert_no_payload_execution()

    def test_script_disguised_as_appimage_is_not_invoked(self):
        image = self.case_root / "shell.AppImage"
        image.write_text(
            '#!/bin/sh\n'
            'printf "executed\\n" > "$RELEASE_CHECK_RUNTIME_SENTINEL"\n'
        )
        for mode in (0o755, 0o644):
            with self.subTest(mode=mode):
                image.chmod(mode)
                _, output = self.check(image, 2)
                self.assertIn("expected a Type 2 ELF AppImage", output)
                self.assert_no_payload_execution()

    def restricted_path(self, missing):
        path = self.case_root / f"without-{missing}"
        path.mkdir()
        for tool in ("dirname", "basename", "mkdir", "mktemp", "rm", "od", "tr", "sed",
                     "python3", "unsquashfs"):
            if tool != missing:
                target = shutil.which(tool)
                self.assertIsNotNone(target, tool)
                (path / tool).symlink_to(target)
        return {**self.env, "PATH": str(path)}

    def test_missing_trusted_tools_fail_closed_without_fallback(self):
        for tool in ("unsquashfs", "python3"):
            with self.subTest(tool=tool):
                _, output = self.check(self.image(), 2, env=self.restricted_path(tool))
                self.assertIn(f"trusted {tool}", output)
                self.assert_no_payload_execution()

    def extractor_path(self, banner, status=0):
        path = self.case_root / "extractor-tool"
        path.mkdir(exist_ok=True)
        extractor = path / "unsquashfs"
        trusted = shutil.which("unsquashfs")
        self.assertIsNotNone(trusted)
        extractor.write_text(
            '#!/bin/sh\n'
            'if [ "$#" -eq 1 ] && [ "$1" = "-version" ]; then\n'
            f'  printf "%s\\n" {shlex.quote(banner)}\n'
            f'  exit {status}\n'
            'fi\n'
            'printf "extraction attempted\\n" > "$RELEASE_CHECK_EXTRACTOR_SENTINEL"\n'
            f'exec {shlex.quote(trusted)} "$@"\n'
        )
        extractor.chmod(0o755)
        return {
            **self.env,
            "PATH": str(path) + os.pathsep + os.environ["PATH"],
            "RELEASE_CHECK_EXTRACTOR_SENTINEL": str(self.case_root / "extractor-ran"),
        }

    def test_old_missing_and_unparseable_extractor_versions_fail_before_extraction(self):
        for banner, status in (
            ("unsquashfs version 4.4 (2019/08/29)", 0),
            ("unsquashfs version 4.5 (2021/07/22)", 1),
            ("unsquashfs version 4.5.0 (2021/07/22)", 0),
            ("", 0), ("", 1), ("unrecognised version", 0),
            ("unsquashfs version 4.5.1-git (2022/03/17)", 0),
            ("unsquashfs version 4.5.1.2 (2022/03/17)", 0),
            ("unsquashfs version 4.5.1", 0),
            ("unsquashfs version 4.5.1 (2022/03/17)", 2),
        ):
            with self.subTest(banner=banner, status=status):
                env = self.extractor_path(banner, status)
                _, output = self.check(self.image(), 2, env=env)
                self.assertIn("trusted unsquashfs >= 4.5.1 required", output)
                self.assertFalse(Path(env["RELEASE_CHECK_EXTRACTOR_SENTINEL"]).exists())
                self.assert_no_payload_execution()

    def test_supported_extractor_version_banners_allow_real_extraction(self):
        for version, status in (("4.5.1", 1), ("4.5.1", 0), ("4.6", 1), ("4.6.1", 0)):
            with self.subTest(version=version, status=status):
                env = self.extractor_path(f"unsquashfs version {version} (2022/03/17)", status)
                sentinel = Path(env["RELEASE_CHECK_EXTRACTOR_SENTINEL"])
                sentinel.unlink(missing_ok=True)
                self.check(self.image(), 0, env=env)
                self.assertTrue(sentinel.exists())
                self.assert_no_payload_execution()

    def test_offset_reader_ignores_untrusted_python_modules(self):
        (self.case_root / "struct.py").write_text(
            'import os\n'
            'open(os.environ["RELEASE_CHECK_RUNTIME_SENTINEL"], "w").write("imported")\n'
            'raise RuntimeError("untrusted module imported")\n'
        )
        env = {**self.env, "PYTHONPATH": str(self.case_root)}
        self.check(self.image(), 0, env=env)
        self.assert_no_payload_execution()

    def test_malformed_and_unsupported_metadata_fail_closed(self):
        # ELF64 little-endian field offsets; each case still carries a valid payload.
        mutations = (
            (8, b"AI\x01"), (4, b"\x03"), (5, b"\x00"), (6, b"\x00"),
            (16, struct.pack("<H", 1)), (20, struct.pack("<I", 0)),
            (52, struct.pack("<H", 0)), (54, struct.pack("<H", 0)),
            (56, struct.pack("<H", 65535)), (58, struct.pack("<H", 1)),
            (60, struct.pack("<H", 0)), (62, struct.pack("<H", 3)),
            (40, struct.pack("<Q", 1 << 63)), (32, struct.pack("<Q", 1 << 63)),
            (64 + 32, struct.pack("<Q", 1 << 63)),
            (384 + 2 * 64 + 32, struct.pack("<Q", 1 << 63)),
        )
        for position, value in mutations:
            with self.subTest(position=position, value=value):
                runtime = bytearray(data_runtime())
                runtime[position:position + len(value)] = value
                _, output = self.check(self.image(runtime), 2)
                self.assertIn("AppImage metadata:", output)
                self.assert_no_payload_execution()

    def test_truncated_or_misplaced_squashfs_is_not_searched_for(self):
        runtime = data_runtime()
        payload = self.payloads["clean"]
        wrong_version = bytearray(payload)
        struct.pack_into("<H", wrong_version, 28, 3)
        for data in (
            b"\x7fELF", runtime, runtime + payload[:80],
            runtime + payload[:struct.unpack_from("<Q", payload, 40)[0] - 1],
            runtime + bytes(64) + payload, runtime + bytes(wrong_version),
        ):
            with self.subTest(size=len(data)):
                image = self.case_root / "broken.AppImage"
                image.write_bytes(data)
                _, output = self.check(image, 2)
                self.assertIn("AppImage metadata:", output)
                self.assert_no_payload_execution()

    def test_extractor_rejects_corrupt_squashfs_tables(self):
        image = self.image(data_runtime())
        data = bytearray(image.read_bytes())
        offset = len(data_runtime())
        struct.pack_into("<Q", data, offset + 64, len(self.payloads["clean"]) + 4096)
        image.write_bytes(data)
        _, output = self.check(image, 2)
        self.assertIn("could not unpack", output)
        self.assertNotIn("AppImage metadata:", output)
        self.assert_no_payload_execution()

    def test_explicit_probe_launches_extracted_apprun_only(self):
        evidence, _ = self.check(self.image(), 0, "--runtime-probe", "--probe-seconds", "1")
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "pass")
        self.assertTrue(self.desktop_sentinel.exists())
        self.assertIn("/squashfs-root/AppRun", self.apprun_sentinel.read_text())

    def test_explicit_probe_still_rejects_environment_created_profiles(self):
        evidence, output = self.check(
            self.image(), 1, "--runtime-probe", "--probe-seconds", "1",
            env={**self.env, "RELEASE_CHECK_CREATE_PROFILE": "1"},
        )
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "fail")
        self.assertIn("E2E unlock created 1 profile(s)", output)
        self.assertTrue(self.apprun_sentinel.exists())
        self.assertTrue(self.desktop_sentinel.exists())

    def test_explicit_probe_still_rejects_a_webdriver_listener(self):
        evidence, output = self.check(
            self.image(), 1, "--runtime-probe", "--probe-seconds", "1",
            env={**self.env, "RELEASE_CHECK_SERVE_WEBDRIVER": "1"},
        )
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "fail")
        self.assertIn("WebDriver endpoint answered HTTP", output)
        self.assertTrue(self.apprun_sentinel.exists())
        self.assertFalse(self.desktop_sentinel.exists())

    def test_explicit_probe_early_exit_is_inconclusive(self):
        evidence, output = self.check(
            self.image(), 2, "--runtime-probe", "--probe-seconds", "1",
            env={**self.env, "RELEASE_CHECK_EXIT_EARLY": "1"},
        )
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "error")
        self.assertIn("app exited early", output)
        self.assertTrue(self.apprun_sentinel.exists())
        self.assertTrue(self.desktop_sentinel.exists())


class HostedFixturePolicy(unittest.TestCase):
    def test_non_hosted_environments_cannot_start_fixture_subprocesses(self):
        for actions, runner in (
            (None, None), ("true", None), (None, "github-hosted"),
            ("false", "github-hosted"), ("true", "self-hosted"),
        ):
            with self.subTest(actions=actions, runner=runner):
                env = {}
                if actions is not None:
                    env["GITHUB_ACTIONS"] = actions
                if runner is not None:
                    env["RUNNER_ENVIRONMENT"] = runner
                with patch.dict(os.environ, env, clear=True), patch("subprocess.run") as process:
                    for operation in (
                        ReleaseCheckAppImage.setUpClass,
                        lambda: run(["gcc", "fixture.c"]),
                        lambda: hosted_subprocess(["untrusted.AppImage", "--appimage-extract"]),
                    ):
                        with self.assertRaisesRegex(RuntimeError, "require GITHUB_ACTIONS=true"):
                            operation()
                    process.assert_not_called()


if __name__ == "__main__":
    require_github_hosted()
    unittest.main(verbosity=2)
