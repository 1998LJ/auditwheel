"""Check whether a platform wheel satisfies its advertised compatibility tags."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zipfile import BadZipFile, ZipFile

from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from auditwheel._vendor.wheel.pkginfo import read_pkg_info_bytes
from auditwheel.error import NonPlatformWheelError, WheelToolsError
from auditwheel.wheeltools import get_wheel_architecture, get_wheel_libc, get_wheel_platforms

if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)


def configure_parser(sub_parsers: Any) -> None:  # noqa: ANN401
    help_ = "Validate a wheel against the platform tags it claims."
    parser = sub_parsers.add_parser("validate", help=help_, description=help_)
    parser.add_argument("WHEEL_FILE", type=Path, help="Path to wheel file.")
    parser.set_defaults(func=execute)


def _validate_wheel_tags(wheel_file: Path) -> list[str]:
    """Return filename platforms, checking for matching WHEEL Tag headers."""
    _, _, _, filename_tags = parse_wheel_filename(wheel_file.name)
    expected = sorted(str(tag) for tag in filename_tags)
    with ZipFile(wheel_file) as archive:
        metadata_paths = [
            name
            for name in archive.namelist()
            if name.count("/") == 1 and name.endswith(".dist-info/WHEEL")
        ]
        if len(metadata_paths) != 1:
            msg = "expected exactly one .dist-info/WHEEL metadata file"
            raise WheelToolsError(msg)
        metadata = read_pkg_info_bytes(archive.read(metadata_paths[0]))
        actual = sorted(metadata.get_all("Tag", []))
        if actual != expected:
            msg = (
                "WHEEL metadata Tag headers do not match the filename: "
                f"expected {expected}, got {actual}"
            )
            raise WheelToolsError(msg)
    return get_wheel_platforms(wheel_file.name)


def _validate_platforms(wheel_file: Path) -> None:
    from auditwheel.wheel_abi import analyze_wheel_abi

    platforms = _validate_wheel_tags(wheel_file)
    if "any" in platforms or all(platform.startswith("linux_") for platform in platforms):
        msg = "wheel must declare a portable manylinux, musllinux, or android platform tag"
        raise WheelToolsError(msg)

    libc = get_wheel_libc(wheel_file.name)
    arch = get_wheel_architecture(wheel_file.name)
    winfo = analyze_wheel_abi(
        libc,
        arch,
        wheel_file,
        frozenset(),
        disable_isa_ext_check=False,
        allow_graft=False,
        args_ldpaths=None,
    )

    for platform in platforms:
        try:
            claimed_policy = winfo.policies.get_policy_by_name(platform)
        except LookupError as error:
            msg = f"unsupported platform tag {platform!r}"
            raise WheelToolsError(msg) from error
        if claimed_policy.priority > winfo.overall_policy.priority:
            msg = f"wheel claims {platform!r} but only satisfies {winfo.overall_policy.name!r}"
            raise WheelToolsError(msg)


def execute(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:  # noqa: ARG001
    wheel_file: Path = args.WHEEL_FILE
    if not wheel_file.is_file():
        logger.error("Cannot access wheel file %s", wheel_file)
        return 1
    try:
        _validate_platforms(wheel_file)
    except (
        BadZipFile,
        InvalidWheelFilename,
        NonPlatformWheelError,
        WheelToolsError,
        OSError,
    ) as error:
        logger.error("Invalid wheel %s: %s", wheel_file.name, error)  # noqa: TRY400
        return 1

    logger.info("%s is valid for all its claimed platform tags", wheel_file.name)
    return 0
