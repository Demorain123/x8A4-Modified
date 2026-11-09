#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import platform
import struct
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "xpf_preflight.c"
MOCK = ROOT / "tests" / "xpf_preflight_mock.c"


def make_fileset(path: pathlib.Path) -> bytes:
    uuid = bytes.fromhex("daf0df00112233445566778820f79b60")
    command = struct.pack("<II", 0x1B, 24) + uuid
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        0x0100000C,  # CPU_TYPE_ARM64
        2,           # ARM64E subtype
        12,          # MH_FILESET
        1,           # ncmds
        len(command),
        0,
        0,
    )
    data = header + command + bytes(range(64))
    path.write_bytes(data)
    return data


def compile_mock(binary: pathlib.Path, expected_sha256: str) -> None:
    linker_libraries = [] if platform.system() == "Darwin" else ["-lcrypto"]
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            '-DXPF_PREFLIGHT_SOURCE_COMMIT="mock-test"',
            '-DXPF_ARCHIVE_SHA256="mock-archive"',
            f'-DXPF_EXPECTED_INPUT_SHA256="{expected_sha256}"',
            str(SOURCE),
            str(MOCK),
            *linker_libraries,
            "-o",
            str(binary),
        ],
        check=True,
    )


def run_json(binary: pathlib.Path, path: pathlib.Path, extra_env=None):
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0"
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [str(binary), str(path)],
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"program did not emit JSON (exit {result.returncode}); "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        ) from error
    return result, report


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="xpf-preflight-test-") as temp:
        root = pathlib.Path(temp)
        binary = root / "xpf-preflight-mock"
        fixture = root / "kernelcache.fixture"
        original = make_fileset(fixture)
        original_hash = hashlib.sha256(original).hexdigest()
        compile_mock(binary, original_hash)

        result, report = run_json(binary, fixture)
        assert result.returncode == 0, result.stderr
        assert report["status"] == "ok"
        assert report["xpf_start"]["status"] == "ok"
        assert report["input"]["sha256"] == original_hash
        assert report["expected_input_sha256"] == original_hash
        assert report["input"]["uuid"] == "daf0df00112233445566778820f79b60"
        assert report["input"]["architecture"] == "arm64e"
        assert report["input_unchanged"] is True
        assert report["source_commit"] == "mock-test"
        assert report["libxpf_sha256"] == "mock-archive"

        values = {key: item["value_hex"] for key, item in report["metrics"].items()}
        assert values == {
	            "kernelConstant.T1SZ_BOOT": "0x000000000000005a",
	            "kernelStruct.task.itk_space": "0x0000000000001234",
	            "kernelStruct.proc.struct_size": "0x0000000000005678",
	            "kernelSymbol.allproc": "0x1111222233334444",
        }, values

        failed_metric_result, failed_metric_report = run_json(
            binary, fixture, {"XPF_MOCK_FAIL_INDEX": "2"}
        )
        assert failed_metric_result.returncode == 3
        assert failed_metric_report["status"] == "error"
        assert failed_metric_report["metrics"]["kernelStruct.proc.struct_size"]["status"] == "unresolved"
        assert failed_metric_report["metrics"]["kernelStruct.proc.struct_size"]["error"] == "mock finder failure"

        changed = root / "changed-kernelcache.fixture"
        changed.write_bytes(original + b"changed")
        changed_result, changed_report = run_json(binary, changed)
        assert changed_result.returncode == 2
        assert changed_report["status"] == "input_error"
        assert changed_report["xpf_start"]["status"] == "not_started"
        assert "does not match" in changed_report["error"]

        invalid = root / "not-a-kernelcache"
        invalid.write_bytes(b"not a mach-o")
        invalid_result, invalid_report = run_json(binary, invalid)
        assert invalid_result.returncode == 2
        assert invalid_report["status"] == "input_error"
        assert invalid_report["xpf_start"]["status"] == "not_started"
        assert "shorter than a Mach-O" in invalid_report["error"]

        link = root / "symlink-to-fixture"
        link.symlink_to(fixture)
        link_result, link_report = run_json(binary, link)
        assert link_result.returncode == 2
        assert link_report["status"] == "input_error"

        directory_result, directory_report = run_json(binary, root)
        assert directory_result.returncode == 2
        assert directory_report["status"] == "input_error"

        assert fixture.read_bytes() == original

    print("PASS: XPF-only mock entry, four explicit resolve calls, JSON, hash, UUID, read-only checks")


if __name__ == "__main__":
    main()
