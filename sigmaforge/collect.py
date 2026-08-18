"""Real-time detection engine.

Streams live Windows process-creation events from the WMI feed
(sigmaforge/feeds/wmi_process_feed.ps1) and runs every process_creation
rule against each event the moment it arrives, using the exact same
``match_event`` evaluator the Tier 1 test suite proves. A detection printed
here is the same rule logic CI validated, firing on real activity on this
host rather than on a JSON fixture.

Only rules whose ``logsource.category`` is ``process_creation`` are loaded:
the WMI feed is a process-creation source, so registry_set, process_access
and create_remote_thread rules cannot fire from it and are reported as
out-of-scope rather than silently ignored.

CLI::

    python -m sigmaforge.collect                 # run until Ctrl+C
    python -m sigmaforge.collect --duration 30   # run for 30 seconds
    python -m sigmaforge.collect --all-events    # also print benign events
    python -m sigmaforge.collect --jsonl         # machine-readable detections

This module is Windows-only (it depends on WMI). It shells out to
PowerShell for the process feed so it needs no extra Python packages.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule

from sigmaforge.evaluator import UnsupportedSigmaFeature, match_event
from sigmaforge.loader import discover_rule_paths, load_rule

FEED_SCRIPT = Path(__file__).resolve().parent / "feeds" / "wmi_process_feed.ps1"
LIVE_CATEGORY = "process_creation"

# ANSI colours, disabled automatically when stdout is not a TTY.
_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


LEVEL_STYLE = {
    "critical": "1;97;41",  # white on red
    "high": "1;91",  # bright red
    "medium": "1;93",  # bright yellow
    "low": "1;96",  # bright cyan
    "informational": "1;90",  # grey
}


class LoadedRule:
    """A rule plus the metadata the collector needs at match time."""

    def __init__(self, path: Path, rule: SigmaRule) -> None:
        self.path = path
        self.rule = rule
        self.title = rule.title or path.stem
        self.level = (rule.level.name.lower() if rule.level else "medium")
        self.techniques = sorted(
            str(t).split(".", 1)[1].upper()
            for t in (rule.tags or [])
            if str(t).startswith("attack.t")
        )

    @property
    def category(self) -> str | None:
        return self.rule.logsource.category


def load_live_rules() -> tuple[list[LoadedRule], list[LoadedRule]]:
    """Return (rules the feed can exercise, rules out of scope for this feed)."""
    live: list[LoadedRule] = []
    other: list[LoadedRule] = []
    for path in discover_rule_paths():
        loaded = LoadedRule(path, load_rule(path))
        if loaded.category == LIVE_CATEGORY:
            live.append(loaded)
        else:
            other.append(loaded)
    return live, other


def _powershell() -> str:
    for exe in ("pwsh", "powershell"):
        if shutil.which(exe):
            return exe
    raise RuntimeError(
        "Neither pwsh nor powershell was found on PATH. The live feed needs "
        "Windows PowerShell."
    )


def _parse_event(line: str) -> dict[str, Any] | None:
    line = line.strip().lstrip("﻿")  # tolerate a UTF-8 BOM on the first line
    if not line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None
    # Drop null-valued keys so the evaluator sees them as absent fields,
    # matching how fixture events omit fields they do not carry.
    return {k: v for k, v in raw.items() if v is not None}


def tail_events(path: Path, proc: subprocess.Popen[str], poll_s: float = 0.1):
    """Yield parsed event dicts by tailing the feed's NDJSON output file.

    The feed writes NDJSON to a file and this follows it. File output is used
    rather than reading the subprocess stdout pipe directly because the
    PowerShell-to-Python pipe proved unreliable for a low-volume, long-lived
    stream (lines stalling or dropping under buffering); a file the feed
    appends to and we follow is dependable.

    Implemented as a binary offset tail: each poll reopens the file, seeks to
    the last byte offset, and reads whatever is new. This is the robust
    pattern on Windows -- a text-mode handle can cache EOF and never see
    later appends, and text-mode tell()/seek arithmetic is invalid. Binary
    byte offsets are exact and a fresh handle always sees appended data. A
    trailing partial line is kept in ``pending`` until its newline arrives.
    """
    offset = 0
    pending = b""
    while True:
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                data = fh.read()
                offset = fh.tell()
        except OSError:
            data = b""

        if data:
            pending += data
            while b"\n" in pending:
                raw_line, pending = pending.split(b"\n", 1)
                event = _parse_event(raw_line.decode("utf-8", "replace"))
                if event is not None:
                    yield event
            continue

        if proc.poll() is not None:
            # Feed has exited: one more read for any final flush, then stop.
            try:
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    tail = fh.read()
            except OSError:
                tail = b""
            if tail:
                offset += len(tail)
                pending += tail
                continue
            if pending.strip():
                event = _parse_event(pending.decode("utf-8", "replace"))
                if event is not None:
                    yield event
            return

        time.sleep(poll_s)


def _fmt_event(event: dict[str, Any]) -> str:
    img = event.get("Image") or event.get("OriginalFileName") or "?"
    cmd = event.get("CommandLine") or ""
    parent = event.get("ParentImage") or "?"
    pid = event.get("ProcessId", "?")
    line = f"    pid {pid}  {img}"
    if cmd and cmd.strip() and cmd.strip() != img:
        line += f"\n    cmd  {cmd}"
    line += f"\n    parent {parent}"
    user = event.get("User")
    if user:
        line += f"\n    user  {user}"
    return line


def run(duration: float | None, all_events: bool, jsonl: bool) -> int:
    if not FEED_SCRIPT.is_file():
        print(f"feed script not found: {FEED_SCRIPT}", file=sys.stderr)
        return 2

    live_rules, other_rules = load_live_rules()
    if not live_rules:
        print("no process_creation rules found to run", file=sys.stderr)
        return 2

    if not jsonl:
        print(_c("1", "SigmaForge live detection"))
        print(
            f"  {len(live_rules)} process_creation rules armed against the live "
            f"WMI feed."
        )
        if other_rules:
            cats = sorted({r.category or "unknown" for r in other_rules})
            print(
                f"  {len(other_rules)} rule(s) not exercised by this feed "
                f"(need {', '.join(cats)} telemetry)."
            )
        window = f"for {duration:.0f}s" if duration else "until Ctrl+C"
        print(f"  Watching real process creation {window}. Detections print below.\n")

    ps = _powershell()

    # The feed writes NDJSON to a temp file (via -OutFile) which we tail.
    # Reading the subprocess stdout pipe directly proved unreliable for this
    # low-volume, long-lived PowerShell stream; a file the feed appends to
    # and we follow is dependable.
    feed_dir = Path(tempfile.mkdtemp(prefix="sigmaforge-feed-"))
    feed_file = feed_dir / "events.ndjson"
    feed_file.touch()

    proc = subprocess.Popen(
        [
            ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(FEED_SCRIPT), "-OutFile", str(feed_file),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    # Drain the feed's stderr on a daemon thread so its baseline line,
    # heartbeats and error notices cannot fill the pipe and block the feed.
    feed_errors: list[str] = []

    def _drain_stderr() -> None:
        assert proc.stderr is not None
        for line in iter(proc.stderr.readline, ""):
            feed_errors.append(line.rstrip())

    threading.Thread(target=_drain_stderr, daemon=True).start()

    # A timer terminates the feed after `duration` seconds; the tail loop
    # then drains remaining lines and stops when the process has exited.
    timer: threading.Timer | None = None
    if duration:
        timer = threading.Timer(duration, proc.terminate)
        timer.daemon = True
        timer.start()

    events_seen = 0
    detections = 0
    by_rule: Counter[str] = Counter()

    try:
        for event in tail_events(feed_file, proc):
            events_seen += 1
            for lr in live_rules:
                try:
                    hit = match_event(lr.rule, event)
                except UnsupportedSigmaFeature:
                    continue
                if not hit:
                    continue
                detections += 1
                by_rule[lr.title] += 1
                if jsonl:
                    print(
                        json.dumps(
                            {
                                "detected_utc": datetime.now(UTC).isoformat(),
                                "rule": lr.title,
                                "level": lr.level,
                                "techniques": lr.techniques,
                                "rule_file": str(lr.path.as_posix()),
                                "event": event,
                            }
                        ),
                        flush=True,
                    )
                else:
                    tech = ", ".join(lr.techniques) or "-"
                    badge = _c(LEVEL_STYLE.get(lr.level, "1"), f" {lr.level.upper()} ")
                    print(f"{badge} {_c('1', lr.title)}  [{tech}]")
                    print(_fmt_event(event))
                    print()

            if all_events and not jsonl and not any(
                match_event(lr.rule, event) for lr in live_rules
            ):
                img = event.get("Image") or event.get("OriginalFileName") or "?"
                print(_c("2", f"  . {img}  (no match)"))
    except KeyboardInterrupt:
        pass
    finally:
        if timer:
            timer.cancel()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(feed_dir, ignore_errors=True)

    if not jsonl:
        print(_c("1", "\nSession summary"))
        print(f"  events processed : {events_seen}")
        print(f"  detections       : {detections}")
        for title, count in by_rule.most_common():
            print(f"    {count:>3}  {title}")
        if events_seen == 0:
            print(
                "  No process-creation events arrived. Try launching a program "
                "while the collector runs."
            )
        # Surface feed diagnostics so a dead or erroring feed is never silent.
        notes = [e for e in feed_errors if e.strip()]
        if notes:
            print(_c("2", "  feed: " + notes[0]))
            errs = [e for e in notes if "poll error" in e or "emit error" in e]
            if errs:
                print(_c("1;91", f"  feed reported {len(errs)} error(s); last: {errs[-1]}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m sigmaforge.collect",
        description="Run SigmaForge rules against live Windows process events.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=None,
        metavar="SECONDS",
        help="stop after this many seconds (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "--all-events",
        action="store_true",
        help="also print benign events that did not match any rule",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="emit one JSON object per detection instead of formatted output",
    )
    args = parser.parse_args(argv)
    try:
        return run(args.duration, args.all_events, args.jsonl)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
