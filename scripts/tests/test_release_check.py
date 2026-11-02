"""Hosted tests of the actual release checker; requires gcc and squashfs-tools.

Fixtures are built only on GitHub-hosted Linux runners. The input runtime is a
native executable that writes a sentinel on *any* invocation, including an
offset/extraction request. SquashFS payloads are real compressed filesystems.
"""

import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
import time
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
        if os.geteuid() == 0:
            raise RuntimeError("release checker permission fixtures require a non-root runner")
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
                    "RELEASE_CHECK_SERVE_WEBDRIVER", "RELEASE_CHECK_SHARED_LOCK",
                    "RELEASE_CHECK_HELPER_PIDS", "RELEASE_CHECK_EXIT_EARLY_ONCE",
                    "RELEASE_CHECK_SETSID_HELPER"):
            self.env.pop(key, None)

    def image(self, runtime=None, payload="clean", mode=0o755, name="untrusted image.AppImage"):
        image = self.case_root / name
        prefix = self.native_runtime if runtime is None else runtime
        image.write_bytes(prefix + self.payloads[payload])
        image.chmod(mode)
        return image

    def check(self, image, expected, *options, env=None, cwd=None):
        report = self.case_root / "report.json"
        report.unlink(missing_ok=True)
        image_path = image if image.is_absolute() else (cwd or self.case_root) / image
        before = None if image_path.is_dir() else (
            image_path.read_bytes(), stat.S_IMODE(image_path.stat().st_mode)
        )
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
        if before is not None:
            self.assertEqual(before, (
                image_path.read_bytes(), stat.S_IMODE(image_path.stat().st_mode)
            ))
        self.assertEqual(result.returncode, expected, output)
        evidence = json.loads(report.read_text())
        self.assertEqual(evidence["graph"], "skipped")
        self.assertEqual(evidence["result"], {0: "pass", 1: "fail", 2: "error"}[expected])
        return evidence, output

    def assert_no_payload_execution(self):
        self.assertFalse(self.apprun_sentinel.exists())
        self.assertFalse(self.desktop_sentinel.exists())

    def aliased_tmpdir_env(self):
        temporary = self.case_root / "temporary"
        temporary.mkdir()
        alias = self.case_root / "temporary-alias"
        alias.symlink_to(temporary, target_is_directory=True)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.resolve(strict=True), temporary.resolve(strict=True))
        return {**self.env, "TMPDIR": str(alias)}

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

    def permission_payload(self, content, mode, label):
        appdir = self.case_root / f"permissions-{label}"
        shutil.copytree(self.fixture_root / "clean", appdir)
        candidate = appdir / "usr/lib/guarded.so"
        candidate.parent.mkdir()
        candidate.write_bytes(content)
        candidate.chmod(mode)
        if mode == 0:
            # Prove this process cannot bypass permissions before building the image.
            with self.assertRaises(PermissionError):
                candidate.read_bytes()
            # mksquashfs must read the input; its per-file action sets the stored mode.
            candidate.chmod(0o644)
        squashfs = self.case_root / f"permissions-{label}.squashfs"
        options = ["-action", "chmod(000)@name(guarded.so)"] if mode == 0 else []
        run([
            "mksquashfs", str(appdir), str(squashfs), "-noappend", "-no-xattrs",
            "-all-root", "-processors", "1", "-comp", "gzip", *options,
        ])
        image = self.image()
        image.write_bytes(self.native_runtime + squashfs.read_bytes())
        return image

    def permission_extractor_env(self):
        path = self.case_root / "permission-extractor"
        path.mkdir(exist_ok=True)
        trusted = shutil.which("unsquashfs")
        self.assertIsNotNone(trusted)
        proof = self.case_root / "extracted-permissions.json"
        extractor = path / "unsquashfs"
        extractor.write_text(
            '#!/usr/bin/python3 -I\n'
            'import json, os, pathlib, stat, subprocess, sys\n'
            'if (os.environ.get("GITHUB_ACTIONS") != "true" or\n'
            '        os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):\n'
            '    raise RuntimeError("hosted fixture required")\n'
            f'result = subprocess.run([{trusted!r}, *sys.argv[1:]], check=False)\n'
            'if result.returncode == 0 and "-d" in sys.argv:\n'
            '    root = pathlib.Path(sys.argv[sys.argv.index("-d") + 1])\n'
            '    candidate = root / "usr/lib/guarded.so"\n'
            '    try:\n'
            '        candidate.read_bytes()\n'
            '        readable = True\n'
            '    except PermissionError:\n'
            '        readable = False\n'
            f'    pathlib.Path({str(proof)!r}).write_text(json.dumps({{\n'
            '        "mode": stat.S_IMODE(candidate.stat().st_mode),\n'
            '        "uid": os.geteuid(), "readable": readable,\n'
            '    }))\n'
            'sys.exit(result.returncode)\n'
        )
        extractor.chmod(0o755)
        return {**self.env, "PATH": str(path) + os.pathsep + os.environ["PATH"]}, proof

    def test_every_regular_squashfs_file_must_actually_be_readable(self):
        env, proof = self.permission_extractor_env()
        for label, content, executables in (
            ("image", b"\x7fELF\0ANVIL_DATA_DIR\0", 2),
            ("data", b"ordinary non-executable data\0", 1),
        ):
            for mode, expected in ((0o644, 0), (0, 2)):
                with self.subTest(label=label, mode=mode):
                    image = self.permission_payload(content, mode, f"{label}-{mode}")
                    evidence, output = self.check(image, expected, env=env)
                    permissions = json.loads(proof.read_text())
                    self.assertNotEqual(permissions["uid"], 0)
                    self.assertEqual(permissions["mode"], mode)
                    self.assertEqual(permissions["readable"], mode != 0)
                    if mode:
                        self.assertEqual(evidence["artifacts"][0]["executables"], executables)
                    else:
                        self.assertIn("Permission denied", output)
                        self.assertIn("could not inspect AppImage contents", output)
                        self.check(image, 2, "--runtime-probe", "--probe-seconds", "1", env=env)
                    self.assert_no_payload_execution()
        image = self.permission_payload(b"\x7fELF\0/wdio/eval\0", 0, "hidden-hook")
        self.check(image, 2, env=env)
        self.assertFalse(json.loads(proof.read_text())["readable"])
        self.assert_no_payload_execution()

    def tool_read_error_env(self, tool, candidate, needle=None, match_and_error=False):
        path = self.case_root / f"fault-{tool}-{needle or 'header'}-{match_and_error}"
        path.mkdir()
        trusted = shutil.which(tool)
        self.assertIsNotNone(trusted)
        proof = path / "read-status"
        wrapper = path / tool
        condition = f'[ "$file" = {shlex.quote(str(candidate))} ]'
        if needle:
            condition += f' && [ "$needle" = {shlex.quote(needle)} ]'
        if match_and_error:
            blocked = path / "unreadable"
            blocked.write_text("unreadable extra grep input")
            blocked.chmod(0)
            operation = f'  {shlex.quote(trusted)} "$@" {shlex.quote(str(blocked))}\n'
        else:
            operation = '  chmod 000 "$file" || exit 3\n'
            operation += f'  {shlex.quote(trusted)} "$@"\n'
        script = (
            '#!/bin/sh\n'
            'file=""; needle=""\n'
            'for arg do needle="$file"; file="$arg"; done\n'
            f'if {condition}; then\n'
        )
        script += operation
        script += (
            '  status=$?\n'
            f'  printf "%s\\n" "$status" > {shlex.quote(str(proof))}\n'
            '  exit "$status"\n'
            'fi\n'
            f'exec {shlex.quote(trusted)} "$@"\n'
        )
        wrapper.write_text(script)
        wrapper.chmod(0o755)
        return {**self.env, "PATH": str(path) + os.pathsep + os.environ["PATH"]}, proof

    def test_actual_od_and_grep_errors_cannot_hide_behind_a_good_marker(self):
        for tool, needle, message, match_and_error in (
            ("od", None, "classification", False),
            ("grep", "tauri-plugin-wdio-webdriver", "hook scan", False),
            ("grep", "ANVIL_DATA_DIR", "marker scan", False),
            ("grep", "ANVIL_DATA_DIR", "marker scan", True),
        ):
            with self.subTest(tool=tool, needle=needle, match_and_error=match_and_error):
                appdir = self.case_root / f"read-error-{message}-{match_and_error}"
                shutil.copytree(self.fixture_root / "clean", appdir)
                candidate = appdir / "guarded.so"
                candidate.write_bytes(b"\x7fELF\0ANVIL_DATA_DIR\0")
                evidence, _ = self.check(appdir, 0)
                self.assertEqual(evidence["artifacts"][0]["executables"], 2)
                env, proof = self.tool_read_error_env(tool, candidate, needle, match_and_error)
                _, output = self.check(appdir, 2, env=env)
                self.assertIn(f"could not read file for {message}", output)
                self.assertGreater(int(proof.read_text()), 1 if tool == "grep" else 0)
                if not match_and_error:
                    with self.assertRaises(PermissionError):
                        candidate.read_bytes()
                self.assert_no_payload_execution()

    def scan_fault_env(self, kind, host):
        path = self.case_root / f"scan-fault-{kind}"
        path.mkdir()
        proof = path / "fault-ran"
        host_opened = path / "host-opened"
        preamble = (
            'import os, pathlib\n'
            f'_host = {str(host)!r}\n'
            f'_proof = pathlib.Path({str(proof)!r})\n'
            f'_host_opened = pathlib.Path({str(host_opened)!r})\n'
            '_real_open = os.open\n'
            'def _fault_open(name, flags, *args, **kwargs):\n'
            '    directory_fd = kwargs.get("dir_fd")\n'
        )
        if kind in ("file-symlink", "directory-symlink"):
            name = "guarded.so" if kind == "file-symlink" else "lib"
            preamble += f'    if name == {name!r} and directory_fd is not None:\n'
            if kind == "file-symlink":
                preamble += '        os.unlink(name, dir_fd=directory_fd)\n'
            else:
                preamble += (
                    '        os.rename(name, "moved-lib", src_dir_fd=directory_fd,\n'
                    '                  dst_dir_fd=directory_fd)\n'
                )
            preamble += (
                '        os.symlink(_host, name, dir_fd=directory_fd)\n'
                '        _proof.write_text("replaced before open")\n'
            )
        preamble += (
            '    fd = _real_open(name, flags, *args, **kwargs)\n'
            '    opened, outside = os.fstat(fd), os.stat(_host)\n'
            '    if (opened.st_dev, opened.st_ino) == (outside.st_dev, outside.st_ino):\n'
            '        _host_opened.write_text("opened outside the extraction tree")\n'
            '    return fd\n'
            'os.open = _fault_open\n'
        )
        if kind in ("change", "io"):
            preamble += (
                '_real_fdopen = os.fdopen\n'
                'class _FaultReader:\n'
                '    def __init__(self, image, filename):\n'
                '        self.image, self.filename, self.header_read = image, filename, False\n'
                '    def __enter__(self):\n'
                '        self.image.__enter__()\n'
                '        return self\n'
                '    def __exit__(self, *args):\n'
                '        return self.image.__exit__(*args)\n'
                '    def fileno(self):\n'
                '        return self.image.fileno()\n'
                '    def read(self, size):\n'
            )
            if kind == "io":
                preamble += (
                    '        if self.header_read:\n'
                    '            _proof.write_text("I/O error after the header")\n'
                    '            raise OSError(5, "injected I/O error after classification")\n'
                )
            preamble += (
                '        data = self.image.read(size)\n'
                '        if not self.header_read:\n'
                '            self.header_read = True\n'
            )
            if kind == "change":
                preamble += (
                    '            with open(self.filename, "ab") as changed:\n'
                    '                changed.write(b"changed after the header")\n'
                    '            _proof.write_text("changed during the scan")\n'
                )
            preamble += (
                '        return data\n'
                'def _fault_fdopen(fd, *args, **kwargs):\n'
                '    filename = os.readlink(f"/proc/self/fd/{fd}")\n'
                '    image = _real_fdopen(fd, *args, **kwargs)\n'
                '    if filename.endswith("/guarded.so"):\n'
                '        return _FaultReader(image, filename)\n'
                '    return image\n'
                'os.fdopen = _fault_fdopen\n'
            )
        python = path / "python3"
        python.write_text(
            '#!/usr/bin/python3 -I\n'
            'import os, subprocess, sys\n'
            'if (os.environ.get("GITHUB_ACTIONS") != "true" or\n'
            '        os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):\n'
            '    raise RuntimeError("hosted fixture required")\n'
            'source = sys.stdin.read()\n'
            'args = sys.argv[3:]\n'
            'if len(args) > 2 and args[0].endswith("/squashfs-root"):\n'
            f'    source = {preamble!r} + source\n'
            'result = subprocess.run([sys.executable, "-I", "-", *args],\n'
            '                        input=source, text=True, check=False)\n'
            'sys.exit(result.returncode)\n'
        )
        python.chmod(0o755)
        env = {**self.env, "PATH": str(path) + os.pathsep + os.environ["PATH"]}
        return env, proof, host_opened

    def test_replacement_changes_and_read_errors_during_appimage_scan_are_fatal(self):
        host = self.case_root / "host"
        host.mkdir()
        host_file = host / "outside.so"
        host_file.write_bytes(b"\x7fELF\0ANVIL_DATA_DIR\0/wdio/eval\0")
        before = host_file.read_bytes()
        for kind, message in (
            ("file-symlink", "Too many levels of symbolic links"),
            ("directory-symlink", "Not a directory"),
            ("change", "file changed during inspection"),
            ("io", "injected I/O error after classification"),
        ):
            with self.subTest(kind=kind):
                image = self.permission_payload(b"\x7fELF\0ANVIL_DATA_DIR\0", 0o644, kind)
                self.check(image, 0)
                target = host if kind == "directory-symlink" else host_file
                env, proof, host_opened = self.scan_fault_env(kind, target)
                _, output = self.check(image, 2, env=env)
                self.assertTrue(proof.exists(), output)
                self.assertIn(message, output)
                self.assertFalse(host_opened.exists(), output)
                self.assertEqual(host_file.read_bytes(), before)
                self.assert_no_payload_execution()

    def test_enumeration_failure_cannot_hide_behind_a_good_marker(self):
        appdir = self.case_root / "enumeration-error"
        shutil.copytree(self.fixture_root / "clean", appdir)
        blocked = appdir / "blocked"
        blocked.mkdir()
        blocked.chmod(0)
        try:
            _, output = self.check(appdir, 2)
            self.assertIn("could not enumerate regular files", output)
            self.assertIn("Permission denied", output)
            self.assert_no_payload_execution()
        finally:
            blocked.chmod(0o755)

    def test_hook_crossing_scan_chunk_boundary_is_rejected(self):
        content = b"\x7fELF" + bytes(1024 * 1024 - 4) + b"/wdio/eval\0"
        image = self.permission_payload(content, 0o644, "split-hook")
        evidence, _ = self.check(image, 1)
        self.assertIn("/wdio/eval", evidence["artifacts"][0]["hits"])
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
        environments = (self.env, self.aliased_tmpdir_env())
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
                for env in environments:
                    for options in ((), ("--runtime-probe", "--probe-seconds", "1")):
                        with self.subTest(tmpdir=env.get("TMPDIR"), options=options):
                            _, output = self.check(image, 2, *options, env=env)
                            self.assertIn("symlink escapes the extraction directory", output)
                            self.assertEqual(host.read_bytes(), before)
                            self.assert_no_payload_execution()

    def test_contained_apprun_symlink_with_aliased_tmpdir_remains_supported(self):
        appdir = self.case_root / "contained-link"
        shutil.copytree(self.fixture_root / "clean", appdir)
        (appdir / "AppRun").rename(appdir / "usr/bin/launcher")
        (appdir / "AppRun").symlink_to("usr/bin/launcher")
        payload = squashfs_payload(appdir, self.case_root / "contained-link.squashfs")
        image = self.image()
        image.write_bytes(self.native_runtime + payload)
        for env in (self.env, self.aliased_tmpdir_env()):
            with self.subTest(tmpdir=env.get("TMPDIR")):
                evidence, _ = self.check(image, 0, env=env)
                self.assertEqual(evidence["artifacts"][0]["executables"], 1)
                self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "skipped")
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
        for version, status in (
            ("4.5.1", 1), ("4.5.1", 0), ("4.6", 1), ("4.6.1", 0), ("4.7.5", 1),
        ):
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
        self.assertNotIn("trusted unsquashfs >= 4.5.1 required", output)
        self.assert_no_payload_execution()

    def list_appimage(self, *args, env=None):
        result = hosted_subprocess(
            ["/bin/bash", str(CHECKER), "--list-appimage", *map(str, args)],
            env=self.env if env is None else env, cwd=self.case_root,
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout + result.stderr
        self.assertFalse(self.runtime_sentinel.exists(), output)
        self.assert_no_payload_execution()
        return result, output

    def test_list_appimage_prints_payload_paths_without_running_it(self):
        runtimes = {"native": None, "elf64-le": data_runtime(),
                    "elf32-be-section-last": data_runtime(1, ">", 20, True)}
        for layout, runtime in runtimes.items():
            with self.subTest(layout=layout):
                image = self.image(runtime, payload="forbidden", mode=0o644)
                before = image.read_bytes()
                result, output = self.list_appimage(image)
                self.assertEqual(result.returncode, 0, output)
                self.assertEqual(
                    sorted(result.stdout.splitlines()),
                    ["AppRun", "usr/bin/anvil-desktop", "usr/lib/libhooks.so"],
                )
                self.assertEqual(before, image.read_bytes())
                self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o644)

    def test_list_appimage_fails_closed(self):
        broken = self.case_root / "broken.AppImage"
        broken.write_bytes(data_runtime())
        for args, env, message in (
            ((broken,), None, "AppImage metadata:"),
            ((self.case_root / "missing.AppImage",), None, "cannot read AppImage"),
            ((self.image(), self.image()), None, "takes no other artifact or option"),
            ((self.image(),), self.restricted_path("unsquashfs"), "trusted unsquashfs"),
            ((self.image(),), self.restricted_path("python3"), "trusted python3"),
        ):
            with self.subTest(message=message):
                result, output = self.list_appimage(*args, env=env)
                self.assertEqual(result.returncode, 2, output)
                self.assertEqual(result.stdout, "")
                self.assertIn(message, output)
        for banner in ("unsquashfs version 4.5.0 (2021/07/22)", "unrecognised version"):
            with self.subTest(banner=banner):
                env = self.extractor_path(banner)
                result, output = self.list_appimage(self.image(), env=env)
                self.assertEqual(result.returncode, 2, output)
                self.assertIn("trusted unsquashfs >= 4.5.1 required", output)
                self.assertFalse(Path(env["RELEASE_CHECK_EXTRACTOR_SENTINEL"]).exists())
        for option in (["--no-graph"], ["--probe-seconds", "1"], ["--runtime-probe"],
                       ["--features", "e2e"], ["--report", "report.json"]):
            with self.subTest(option=option):
                for order in ((*option, "--list-appimage", self.image()),
                              ("--list-appimage", self.image(), *option)):
                    result = hosted_subprocess(
                        ["/bin/bash", str(CHECKER), *map(str, order)],
                        env=self.env, cwd=self.case_root,
                        capture_output=True, text=True, timeout=30,
                    )
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 2, output)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("takes no other artifact or option", output)
                    self.assertFalse((self.case_root / "report.json").exists())
                    self.assertFalse(self.runtime_sentinel.exists(), output)
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

    def shared_lock_env(self):
        """The fixture app starts a SIGTERM-ignoring helper that holds a lock
        every launch shares, like WebView2's browser process and its user data
        folder on Windows; a launch while the lock is held exits early."""
        helper_pids = self.case_root / "helper-pids"
        self.addCleanup(self.kill_helpers, helper_pids)
        return helper_pids, {
            **self.env,
            "RELEASE_CHECK_SHARED_LOCK": str(self.case_root / "shared.lock"),
            "RELEASE_CHECK_HELPER_PIDS": str(helper_pids),
        }

    @staticmethod
    def helper_pid_list(helper_pids):
        return [int(pid) for pid in helper_pids.read_text().split()] if helper_pids.exists() else []

    @staticmethod
    def running(pid):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return False
        return state != "Z"

    def kill_helpers(self, helper_pids):
        for pid in self.helper_pid_list(helper_pids):
            if self.running(pid):
                os.kill(pid, 9)

    def probe_two_images(self, env):
        report = self.case_root / "report.json"
        result = hosted_subprocess(
            ["/bin/bash", str(CHECKER), "--no-graph", "--report", str(report),
             "--runtime-probe", "--probe-seconds", "1",
             str(self.image(name="first.AppImage")), str(self.image(name="second.AppImage"))],
            env=env, cwd=self.case_root, capture_output=True, text=True, timeout=90,
        )
        output = result.stdout + result.stderr
        self.assertFalse(self.runtime_sentinel.exists(), output)
        return result, output, json.loads(report.read_text())

    def assert_helpers_gone(self, helper_pids, count, output):
        pids = self.helper_pid_list(helper_pids)
        self.assertEqual(len(pids), count, output)
        deadline = time.monotonic() + 5
        while any(self.running(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual([pid for pid in pids if self.running(pid)], [], output)

    def test_each_probe_stops_the_apps_helpers_before_the_next_probe(self):
        helper_pids, env = self.shared_lock_env()
        result, output, evidence = self.probe_two_images(env)
        self.assertEqual(result.returncode, 0, output)
        self.assertEqual(evidence["result"], "pass")
        self.assertEqual([a["runtime_probe"] for a in evidence["artifacts"]], ["pass", "pass"], output)
        self.assertNotIn("exited early", output)
        self.assert_helpers_gone(helper_pids, 2, output)

    def test_helpers_of_an_app_that_exits_early_do_not_poison_the_next_probe(self):
        # The first launch starts its lock-holding helper and exits at once,
        # so the helper is reparented before the probe ever looks at it.
        helper_pids, env = self.shared_lock_env()
        env["RELEASE_CHECK_EXIT_EARLY_ONCE"] = str(self.case_root / "exited-once")
        result, output, evidence = self.probe_two_images(env)
        self.assertEqual(result.returncode, 2, output)
        self.assertEqual(evidence["result"], "error")
        self.assertEqual([a["runtime_probe"] for a in evidence["artifacts"]], ["error", "pass"], output)
        self.assertEqual(output.count("app exited early"), 1, output)
        self.assertNotIn("shared lock is in use", output)
        self.assert_helpers_gone(helper_pids, 2, output)

    def test_detached_helpers_of_an_app_that_exits_early_do_not_poison_the_next_probe(self):
        # The helper leaves the app's session and process group, and the app
        # exits at once, before the probe could see the helper as its child.
        helper_pids, env = self.shared_lock_env()
        env["RELEASE_CHECK_EXIT_EARLY_ONCE"] = str(self.case_root / "exited-once")
        env["RELEASE_CHECK_SETSID_HELPER"] = "1"
        result, output, evidence = self.probe_two_images(env)
        self.assertEqual(result.returncode, 2, output)
        self.assertEqual([a["runtime_probe"] for a in evidence["artifacts"]], ["error", "pass"], output)
        self.assertEqual(output.count("app exited early"), 1, output)
        self.assertNotIn("shared lock is in use", output)
        self.assert_helpers_gone(helper_pids, 2, output)

    def test_lock_held_outside_the_probe_is_still_an_inconclusive_early_exit(self):
        helper_pids, env = self.shared_lock_env()
        with open(self.case_root / "shared.lock", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            evidence, output = self.check(self.image(), 2, "--runtime-probe", "--probe-seconds", "1", env=env)
        self.assertEqual(evidence["artifacts"][0]["runtime_probe"], "error")
        self.assertIn("app exited early", output)
        self.assertIn("shared lock is in use", output)
        self.assertEqual(self.helper_pid_list(helper_pids), [])


def windows_probe_script():
    """The PowerShell the checker runs on Windows, as the checker writes it."""
    text = CHECKER.read_text()
    start = text.index("cat <<'PS1'\n") + len("cat <<'PS1'\n")
    return text[start:text.index("\nPS1\n", start)] + "\n"


class WindowsProbeTreeSelection(unittest.TestCase):
    """Which processes the Windows cleanup treats as the probed app's tree.

    Runs the checker's own selection function in PowerShell on the hosted
    Linux runner with process tables given as data (no Windows API involved).
    """

    CASES = r"""
function P($id, $parent, $ticks) { [pscustomobject]@{ Id = $id; ParentId = $parent; Ticks = [long]$ticks; Name = "p$id" } }
$cases = [ordered]@{}
# The app (100) with its browser (200) and the browser's child (300); an
# unrelated process (400) and another launch of the same executable (600).
$cases.running = @{ all = @((P 100 1 1000), (P 200 100 1010), (P 300 200 1020), (P 400 1 1005), (P 600 1 1005)); known = @{ 100 = [long]1000 } }
# The app exited and an unrelated process reuses its id, with a child of its own.
$cases.reused_root = @{ all = @((P 100 7 5000), (P 500 100 5100), (P 200 100 1010), (P 300 200 1020)); known = @{ 100 = [long]1000 } }
# Only a process reusing the app's id is left.
$cases.reused_root_only = @{ all = @((P 100 7 5000), (P 501 100 5100)); known = @{ 100 = [long]1000 } }
# A process naming the app's id as parent but older than the app is not its child.
$cases.older_than_parent = @{ all = @((P 100 1 1000), (P 700 100 900)); known = @{ 100 = [long]1000 } }
# The browser (200, seen before) exited and its id was reused; its own child (300) remains.
$cases.reused_helper = @{ all = @((P 100 1 1000), (P 200 9 6000), (P 800 200 6100), (P 300 200 1020)); known = @{ 100 = [long]1000; 200 = [long]1010 } }
foreach ($k in $cases.Keys) {
  $c = $cases[$k]
  $ids = @(Select-ProbeTree $c.all $c.known | ForEach-Object { $_.Id } | Sort-Object)
  "$k=" + ($ids -join ',')
}
# Identifying the app: this checker's shell is 10; the app runs C:\a\anvil-desktop.exe.
function A($id, $parent, $ticks, $path) { [pscustomobject]@{ Id = $id; ParentId = $parent; Ticks = [long]$ticks; Name = 'anvil-desktop.exe'; Path = $path } }
function S($id, $parent, $ticks) { [pscustomobject]@{ Id = $id; ParentId = $parent; Ticks = [long]$ticks; Name = 'bash.exe'; Path = 'C:\git\bash.exe' } }
$isExe = { param($path) $path -eq 'C:\a\anvil-desktop.exe' }
$finds = [ordered]@{}
# Ours (shell 10 -> job 20 -> app 30) next to another launch of the same executable (shell 11 -> 21 -> 31).
$finds.ours = @((S 10 1 100), (S 20 10 200), (A 30 20 300 'C:\a\anvil-desktop.exe'), (S 11 1 100), (S 21 11 200), (A 31 21 250 'C:\a\anvil-desktop.exe'))
$finds.other_launch_only = @((S 10 1 100), (S 11 1 100), (S 21 11 200), (A 31 21 250 'C:\a\anvil-desktop.exe'))
# The job's id now belongs to a younger process: the chain is broken.
$finds.reused_parent = @((S 10 1 100), (S 20 10 400), (A 30 20 300 'C:\a\anvil-desktop.exe'))
$finds.before_probe = @((S 10 1 100), (S 20 10 120), (A 30 20 140 'C:\a\anvil-desktop.exe'))
$finds.other_path = @((S 10 1 100), (S 20 10 200), (A 30 20 300 'C:\b\anvil-desktop.exe'))
foreach ($k in $finds.Keys) {
  $app = Find-ProbeApp $finds[$k] 10 150 'anvil-desktop.exe' $isExe
  "find_$k=" + $(if ($app) { $app.Id } else { '' })
}
"""

    def test_app_and_tree_are_identified_without_strangers(self):
        require_github_hosted()
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            raise RuntimeError("hosted fixture dependency missing: pwsh")
        with tempfile.TemporaryDirectory(prefix="release-check-pwsh-") as temp:
            script = Path(temp) / "probe-tree.ps1"
            script.write_text(windows_probe_script())
            command = "$env:PROBE_MODE = 'library'; . '" + str(script) + "'\n" + self.CASES
            result = hosted_subprocess(
                [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=120,
            )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        got = dict(line.split("=", 1) for line in result.stdout.split() if "=" in line)
        self.assertEqual(got, {
            "running": "100,200,300",
            "reused_root": "200,300",
            "reused_root_only": "",
            "older_than_parent": "100",
            "reused_helper": "100,300",
            "find_ours": "30",
            "find_other_launch_only": "",
            "find_reused_parent": "",
            "find_before_probe": "",
            "find_other_path": "",
        }, output)


class HostedFixturePolicy(unittest.TestCase):
    def test_root_cannot_bypass_permission_fixtures(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        with patch.dict(os.environ, env, clear=True), patch("os.geteuid", return_value=0):
            with patch("subprocess.run") as process:
                with self.assertRaisesRegex(RuntimeError, "require a non-root runner"):
                    ReleaseCheckAppImage.setUpClass()
                process.assert_not_called()

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
