from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.scrape.xfind import XFindPlugin

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@pytest.fixture
def mock_target(target_unix: Target, fs_unix) -> Target:
    target_unix.add_plugin(XFindPlugin)

    fs_unix.makedirs("/opt")
    fs_unix.map_file_fh("/opt/alpha.txt", BytesIO(b"AAAABBBBCCCC"))
    fs_unix.map_file_fh("/opt/bravo.bin", BytesIO((b"\x00" * 8) + b"ABCD" + (b"\x00" * 8)))
    fs_unix.map_file_fh("/opt/charlie.bin", BytesIO((b"\x00" * 8) + b"\xab\xcd" + (b"\x00" * 8)))

    return target_unix


def test_xfind(mock_target: Target) -> None:
    results = list(mock_target.xfind(["ABCD"]))

    assert len(results) == 2

    assert results[0].filename == "bravo.bin"
    assert results[0].path == "/opt/bravo.bin"
    assert results[0].offset == 8
    assert results[0].needle == "ABCD"
    assert results[0].codec == "utf-8"

    assert results[1].filename == "charlie.bin"
    assert results[1].path == "/opt/charlie.bin"
    assert results[1].offset == 8
    assert results[1].needle == "ABCD"
    assert results[1].codec == "hex"


def test_xfind_needle_file(mock_target: Target, tmp_path: Path) -> None:
    needle_file = tmp_path.joinpath("needles.txt")
    needle_file.write_text("ABCD\n")

    results = list(mock_target.xfind(needle_file=needle_file))

    assert len(results) == 2
    assert all(result.offset == 8 for result in results)


def test_xfind_regex(mock_target: Target) -> None:
    results = list(mock_target.xfind([r"[a-d]{4}"], regex=True, ignore_case=True, path="/opt"))

    assert len(results) == 1
    assert results[0].filename == "bravo.bin"
    assert results[0].path == "/opt/bravo.bin"
    assert results[0].offset == 8
    assert results[0].match == b"ABCD"
