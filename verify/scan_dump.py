#!/usr/bin/env python3
"""Volatility-style memory-scraping scanner for the Zero-Trust Secrets Manager.

Standalone, dependency-free. mmaps a process dump (e.g. a `.dmp` produced by
MiniDumpWriteDump, or any raw memory image) and searches it for a canary string
in BOTH its UTF-8 and UTF-16LE encodings, printing every hit offset.

This is the "memory-scraping script" used for MANUAL verification, independent
of the Rust `dumper`. It exists so a human can confirm the finding by hand.

Exit codes (chosen so it slots into shell pipelines):
    0  -> canary NOT found (clean: what we WANT for locked / post-clip dumps)
    2  -> canary FOUND     (leak: expected only for the positive control)
    1  -> usage / IO error

Usage:
    python scan_dump.py <dump-file> <canary>

The canary is searched as UTF-8 and UTF-16LE by default (both, always).
"""

import mmap
import sys


def find_all(haystack: mmap.mmap, needle: bytes):
    """Yield every start offset of `needle` in `haystack` (overlapping)."""
    if not needle:
        return
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return
        yield idx
        start = idx + 1  # allow overlapping matches


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: python scan_dump.py <dump-file> <canary>\n")
        return 1

    dump_path, canary = argv[1], argv[2]

    try:
        needles = {
            "utf-8": canary.encode("utf-8"),
            "utf-16le": canary.encode("utf-16-le"),
        }
    except UnicodeEncodeError as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"cannot encode canary: {exc}\n")
        return 1

    try:
        with open(dump_path, "rb") as fh:
            # mmap the whole file read-only; scanning stays out of the heap.
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                total = 0
                for enc, needle in needles.items():
                    hits = list(find_all(mm, needle))
                    total += len(hits)
                    if hits:
                        preview = ", ".join(f"0x{o:x}" for o in hits[:16])
                        more = "" if len(hits) <= 16 else f", (+{len(hits) - 16} more)"
                        print(f"[{enc}] {len(hits)} hit(s): {preview}{more}")
                    else:
                        print(f"[{enc}] 0 hits")
    except OSError as exc:
        sys.stderr.write(f"error reading {dump_path}: {exc}\n")
        return 1

    print(f"canary: {canary!r}")
    print(f"total hits: {total}")
    if total > 0:
        print("RESULT: canary PRESENT in dump")
        return 2
    print("RESULT: canary ABSENT from dump")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
