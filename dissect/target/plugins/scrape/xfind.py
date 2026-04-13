from __future__ import annotations

import codecs
import re
import string
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.scrape import find_needles
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator


re_NOFLAG = 0  # re.NOFLAG is Python 3.11 and newer only

XFindMatchRecord = TargetRecordDescriptor(
    "xfind/match",
    [
        ("string", "filename"),
        ("path", "path"),
        ("varint", "offset"),
        ("string", "needle"),
        ("string", "codec"),
        ("bytes", "match"),
    ],
)


class XFindPlugin(Plugin):
    """Find needles in files on the target filesystems."""

    def check_compatible(self) -> None:
        pass

    @arg("-n", "--needles", nargs="*", metavar="NEEDLES", help="needles to search for")
    @arg("-nf", "--needle-file", type=Path, help="file containing the needles to search for")
    @arg("-e", "--encoding", help="encode text needles with these comma separated encodings")
    @arg("--regex", action="store_true", help="parse needles as regex patterns")
    @arg("--no-hex-decode", action="store_true", help="do not automatically add decoded hex needles")
    @arg("-i", "--ignore-case", action="store_true", help="case insensitive search")
    @arg("-p", "--path", default="/", help="path on target(s) to recursively scan")
    @export(record=XFindMatchRecord)
    def xfind(
        self,
        needles: list[str] | None = None,
        needle_file: Path | None = None,
        encoding: str = "",
        no_hex_decode: bool = False,
        regex: bool = False,
        ignore_case: bool = False,
        path: str = "/",
    ) -> Iterator[XFindMatchRecord]:
        all_needles = set(needles or [])
        if needle_file and needle_file.exists():
            with needle_file.open("r") as fh:
                for line in fh:
                    if line := line.strip():
                        if line.startswith("#"):
                            self.target.log.warning("Ignoring needle %r", line)
                        else:
                            all_needles.add(line)

        self.target.log.info("Loaded %s needles", len(all_needles))

        encodings = set()
        for codec in (encoding or "").split(","):
            if not (codec := codec.strip()):
                continue

            try:
                codecs.lookup(codec)
            except LookupError:
                self.target.log.warning("Unknown encoding: %s", codec)
            else:
                encodings.add(codec)

        needle_lookup: dict[bytes | re.Pattern, tuple[str, str]] = {}
        for needle in all_needles:
            encoded_needle = needle.encode("utf-8")
            needle_lookup[encoded_needle] = (needle, "utf-8")

            if not no_hex_decode and len(needle) % 2 == 0 and all(c in string.hexdigits for c in needle):
                encoded_needle = bytes.fromhex(needle)
                needle_lookup[encoded_needle] = (needle, "hex")

            for codec in encodings:
                try:
                    encoded_needle = needle.encode(codec)
                except UnicodeEncodeError:  # noqa: PERF203
                    self.target.log.warning("Cannot encode needle with %s: %s", codec, needle)
                else:
                    needle_lookup[encoded_needle] = (needle, codec)

        if not needle_lookup:
            self.target.log.error("No needles to search for (use '--needles' or '--needle-file')")
            return

        if ignore_case or regex:
            tmp = {}
            for encoded_needle, needle_desc in needle_lookup.items():
                encoded_needle = encoded_needle if regex else re.escape(encoded_needle)
                tmp[re.compile(encoded_needle, re.IGNORECASE if ignore_case else re_NOFLAG)] = needle_desc
            needle_lookup = tmp

        root = self.target.fs.path(path)
        if not root.exists() or not root.is_dir():
            self.target.log.error("Not a directory: '%s'", path)
            return

        for entry in self.target.fs.recurse(path):
            try:
                if not entry.is_file():
                    continue

                with entry.open() as fh:
                    for needle, offset, match in find_needles(fh, list(needle_lookup.keys())):
                        original_needle, codec = needle_lookup[needle]
                        yield XFindMatchRecord(
                            filename=entry.name,
                            path=entry.path,
                            offset=offset,
                            needle=original_needle,
                            codec=codec,
                            match=match.group() if match else original_needle.encode(),
                            _target=self.target,
                        )

            except Exception as e:  # noqa: BLE001
                self.target.log.warning("Could not scan %s: %s", entry, e)
                self.target.log.debug("", exc_info=e)
