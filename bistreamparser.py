#!/usr/bin/env python3
"""
bistreamparser.py

Walks a Dionaea honeypot bistream directory tree, parses the metadata encoded
in each bistream filename, reads the raw capture payload, and emits one
newline-delimited JSON (NDJSON) record per file to stdout.

Intended for use in a pipeline:
    python3 bistreamparser.py /var/dionaea/bistreams | logger -t dionaea
    python3 bistreamparser.py /var/dionaea/bistreams | nc localhost 5044

Filename format expected by Dionaea:
    <protocol>-<dst_ip>-<dst_port>-<src_ip>-?-<year>-<month>-<daytime>

Output format (NDJSON, one record per line):
    {"protocol": "tcp", "dst_ip": "...", "src_ip": "...", "dst_port": "...",
     "timestamp": "...", "request": "..."}

Author:  Jesse G. Lands <jesselands@jesselands.com>
GitHub:  https://github.com/usedtire
License: GPL-3.0
"""

__author__ = "Jesse G. Lands"
__email__  = "jesselands@jesselands.com"
__github__ = "https://github.com/usedtire"
__version__ = "1.1.0"

import sys
import os
import json
import argparse
import logging
from os import listdir
from os.path import isfile, join

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Filename parser
# ---------------------------------------------------------------------------
def parse_bistream_filename(filename: str) -> dict | None:
    """
    Decode the metadata embedded in a Dionaea bistream filename.

    Expected format:
        <protocol>-<dst_ip>-<dst_port>-<src_ip>-<seq?>-<year>-<month>-<daytime>

    Returns a dict with keys: protocol, dst_ip, src_ip, dst_port, timestamp
    Returns None and logs a warning if the filename cannot be parsed.
    """
    try:
        parts = filename.split("-", 1)
        if len(parts) != 2:
            raise ValueError("Missing protocol prefix separator")

        protocol = parts[0]
        remainder = parts[1].split("-")

        # remainder layout: [dst_ip, dst_port, src_ip, seq, year, month, daytime]
        if len(remainder) < 7:
            raise ValueError(f"Expected ≥7 dash-separated fields, got {len(remainder)}")

        dst_ip   = remainder[0]
        dst_port = remainder[1]
        src_ip   = remainder[2]
        # remainder[3] is an internal sequence field — skip
        year     = remainder[4]
        month    = remainder[5]
        daytime  = remainder[6]

        return {
            "protocol":  protocol,
            "dst_ip":    dst_ip,
            "src_ip":    src_ip,
            "dst_port":  dst_port,
            "timestamp": f"{year}-{month}-{daytime}",
        }

    except (ValueError, IndexError) as exc:
        log.warning("Skipping unparseable filename '%s': %s", filename, exc)
        return None


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------
def process_directory(root_path: str, dry_run: bool = False) -> int:
    """
    Recursively walk root_path, process every bistream file found, and
    emit one NDJSON record per file to stdout.

    If dry_run is True, files are parsed and printed but NOT deleted.
    Returns the count of successfully processed files.
    """
    processed = 0
    errors    = 0

    try:
        subdirs = [f.path for f in os.scandir(root_path) if f.is_dir()]
    except PermissionError as exc:
        log.error("Cannot scan root directory '%s': %s", root_path, exc)
        return 0

    for directory in subdirs:
        try:
            files = [f for f in listdir(directory) if isfile(join(directory, f))]
        except PermissionError as exc:
            log.warning("Cannot list directory '%s': %s", directory, exc)
            continue

        for filename in files:
            filepath = join(directory, filename)

            # --- Parse filename metadata ---
            record = parse_bistream_filename(filename)
            if record is None:
                errors += 1
                continue

            # --- Read payload ---
            try:
                with open(filepath, "r", errors="replace") as fh:
                    raw_content = fh.read()
            except OSError as exc:
                log.warning("Cannot read file '%s': %s", filepath, exc)
                errors += 1
                continue

            # --- Build and emit NDJSON record ---
            record["request"] = raw_content
            print(json.dumps(record), flush=True)

            # --- Delete source file (skip in dry-run) ---
            if not dry_run:
                try:
                    os.remove(filepath)
                except OSError as exc:
                    log.warning("Could not delete '%s': %s", filepath, exc)
            else:
                log.info("[dry-run] would delete: %s", filepath)

            processed += 1

    log.info("Done. Processed: %d  Errors/skipped: %d", processed, errors)
    return processed


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Parse Dionaea bistream files and emit NDJSON records to stdout. "
            "By default, successfully processed files are deleted from disk."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard run — process and delete
  python3 bistreamparser.py /var/dionaea/bistreams

  # Dry run — parse and print, no deletions
  python3 bistreamparser.py --dry-run /var/dionaea/bistreams

  # Verbose logging to stderr, pipe JSON to Logstash
  python3 bistreamparser.py -v /var/dionaea/bistreams | nc localhost 5044
        """,
    )
    p.add_argument(
        "path",
        help="Root directory of the Dionaea bistream tree to process.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Parse and print records but do NOT delete source files.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging to stderr.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if not os.path.isdir(args.path):
        parser.error(f"Path does not exist or is not a directory: {args.path}")

    if args.dry_run:
        log.warning("DRY-RUN mode enabled — no files will be deleted.")

    process_directory(args.path, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
