from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from auditwheel.architecture import Architecture
from auditwheel.libc import Libc
from auditwheel.main import main
from auditwheel.main_validate import execute
from auditwheel.policy import WheelPolicies


def make_wheel(tmp_path: Path, platform: str, *, tags: list[str] | None = None) -> Path:
    wheel = tmp_path / f"widget-1.0-cp311-cp311-{platform}.whl"
    if tags is None:
        tags = [f"cp311-cp311-{tag}" for tag in platform.split(".")]
    metadata = "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\n" + "".join(
        f"Tag: {tag}\n" for tag in tags
    )
    with ZipFile(wheel, "w") as archive:
        archive.writestr("widget-1.0.dist-info/WHEEL", metadata)
    return wheel


def patch_analysis(
    monkeypatch: pytest.MonkeyPatch,
    policy_name: str,
    *,
    architecture: Architecture = Architecture.x86_64,
) -> None:
    policies = WheelPolicies(libc=Libc.GLIBC, arch=architecture)
    policy = policies.get_policy_by_name(policy_name)

    def analyze(libc, arch, file, exclude, **kwargs):
        assert libc == Libc.GLIBC
        assert arch == architecture
        assert file.suffix == ".whl"
        assert exclude == frozenset()
        assert kwargs == {
            "disable_isa_ext_check": False,
            "allow_graft": False,
            "args_ldpaths": None,
        }
        return SimpleNamespace(policies=policies, overall_policy=policy)

    monkeypatch.setattr("auditwheel.wheel_abi.analyze_wheel_abi", analyze)


def validate(wheel: Path) -> int:
    return execute(argparse.Namespace(WHEEL_FILE=wheel), argparse.ArgumentParser())


def test_valid_older_manylinux_and_aliases(tmp_path: Path, monkeypatch):
    patch_analysis(monkeypatch, "manylinux_2_17_x86_64")
    wheel = make_wheel(tmp_path, "manylinux_2_17_x86_64.manylinux2014_x86_64")
    assert validate(wheel) == 0


def test_validate_other_architecture_without_host_binary(tmp_path: Path, monkeypatch):
    patch_analysis(monkeypatch, "manylinux_2_17_aarch64", architecture=Architecture.aarch64)
    wheel = make_wheel(tmp_path, "manylinux2014_aarch64")
    assert validate(wheel) == 0


def test_valid_portable_tag_with_linux_fallback(tmp_path: Path, monkeypatch):
    patch_analysis(monkeypatch, "manylinux_2_17_x86_64")
    wheel = make_wheel(tmp_path, "linux_x86_64.manylinux2014_x86_64")
    assert validate(wheel) == 0


def test_claimed_policy_too_old(tmp_path: Path, monkeypatch, caplog):
    patch_analysis(monkeypatch, "manylinux_2_28_x86_64")
    wheel = make_wheel(tmp_path, "manylinux_2_17_x86_64")
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "only satisfies" in caplog.text


@pytest.mark.parametrize("platform", ["linux_x86_64", "any"])
def test_reject_nonportable_tags(tmp_path: Path, platform: str, caplog):
    wheel = make_wheel(tmp_path, platform)
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "portable manylinux, musllinux, or android" in caplog.text


@pytest.mark.parametrize("tags", [[], ["cp311-cp311-manylinux_2_28_x86_64"]])
def test_reject_missing_or_mismatched_metadata_tags(tmp_path: Path, tags: list[str], caplog):
    wheel = make_wheel(tmp_path, "manylinux_2_17_x86_64", tags=tags)
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "Tag headers do not match" in caplog.text


def test_reject_compressed_metadata_tags(tmp_path: Path, caplog):
    compressed = "cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64"
    wheel = make_wheel(
        tmp_path,
        "manylinux_2_17_x86_64.manylinux2014_x86_64",
        tags=[compressed],
    )
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "Tag headers do not match" in caplog.text


def test_reject_duplicate_metadata_tag(tmp_path: Path, caplog):
    tag = "cp311-cp311-manylinux_2_17_x86_64"
    wheel = make_wheel(tmp_path, "manylinux_2_17_x86_64", tags=[tag, tag])
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "Tag headers do not match" in caplog.text


def test_reject_missing_metadata(tmp_path: Path, caplog):
    wheel = tmp_path / "widget-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("widget/__init__.py", "")
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "exactly one" in caplog.text


def test_reject_invalid_zip_and_missing_wheel(tmp_path: Path):
    wheel = tmp_path / "widget-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    assert validate(wheel) == 1
    wheel.write_bytes(b"invalid zip")
    assert validate(wheel) == 1


def test_reject_unknown_policy(tmp_path: Path, monkeypatch, caplog):
    patch_analysis(monkeypatch, "manylinux_2_28_x86_64")
    wheel = make_wheel(tmp_path, "manylinux_999_999_x86_64")
    with caplog.at_level(logging.ERROR):
        assert validate(wheel) == 1
    assert "unsupported platform tag" in caplog.text


def test_cli_validate_command(tmp_path: Path, monkeypatch):
    patch_analysis(monkeypatch, "manylinux_2_17_x86_64")
    wheel = make_wheel(tmp_path, "manylinux_2_17_x86_64")
    monkeypatch.setattr(sys, "argv", ["auditwheel", "validate", str(wheel)])
    assert main() == 0


def test_real_pure_wheel_rejected():
    wheel = (
        Path(__file__).resolve().parents[1] / "bundled-wheels/plumbum-1.6.8-py2.py3-none-any.whl"
    )
    assert validate(wheel) == 1
