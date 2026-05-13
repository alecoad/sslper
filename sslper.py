#!/usr/bin/env python3
"""sslper — validate Nessus SSL findings (20007, 26928) on Kali via sslscan."""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Optional

CHECK_SSLV2V3 = "sslv2v3"
CHECK_WEAK = "weak"

CHECK_TITLES = {
    CHECK_SSLV2V3: "SSL Version 2 and 3 Protocol Detection",
    CHECK_WEAK: "SSL Weak Cipher Suites Supported",
}

# Skip the parts of sslscan we don't need for either check — heartbleed,
# renegotiation, compression, cert fetch, fallback, group/sig listing.
COMMON_SKIPS = [
    "--no-renegotiation",
    "--no-compression",
    "--no-heartbleed",
    "--no-check-certificate",
    "--no-fallback",
    "--no-groups",
    "--no-sigs",
]

WEAK_NAME_PATTERNS = [
    re.compile(r"\bNULL\b", re.I),
    re.compile(r"\banon\b", re.I),
    re.compile(r"\bADH-", re.I),
    re.compile(r"\bAECDH-", re.I),
    re.compile(r"\bEXP(ORT)?-", re.I),
    re.compile(r"\bDES-(?!CBC3)", re.I),
    re.compile(r"\bRC2-", re.I),
    re.compile(r"\bRC4", re.I),
    re.compile(r"\bIDEA-", re.I),
    re.compile(r"-MD5\b", re.I),
]

CIPHER_LINE_RE = re.compile(
    r"^\s*(Preferred|Accepted)\s+(\S+)\s+(\d+)\s*bits\s+(\S+)(.*)$"
)
PROTO_LINE_RE = re.compile(r"^\s*(SSLv2|SSLv3)\s+(enabled|disabled)\s*$", re.I)

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _render(s: str) -> str:
    """Return `s` as-is in color mode, or with ANSI escapes stripped otherwise."""
    return s if Color.enabled else _strip_ansi(s)


def _vlen(s: str) -> int:
    return len(_strip_ansi(s))


class Color:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    enabled = True

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"{code}{text}{cls.RESET}"


@dataclass
class HostResult:
    target: str
    status: str  # "VULNERABLE", "NOT VULNERABLE", "ERROR"
    evidence: list = field(default_factory=list)  # full detail view (incl. context)
    triggers: list = field(default_factory=list)  # subset that drove VULNERABLE; for summary cell
    error: Optional[str] = None


def parse_targets(args_targets, file_path):
    targets = []
    seen = set()

    def add(t):
        t = t.strip()
        if not t or t.startswith("#"):
            return
        if ":" not in t:
            print(f"[!] skipping '{t}': missing :port", file=sys.stderr)
            return
        if t in seen:
            return
        seen.add(t)
        targets.append(t)

    if file_path:
        try:
            with open(file_path) as f:
                for line in f:
                    add(line.split("#", 1)[0])
        except OSError as e:
            print(f"[!] cannot read targets file: {e}", file=sys.stderr)
            sys.exit(2)
    for t in args_targets or []:
        add(t)
    return targets


def run_sslscan(target: str, check: str, timeout: int) -> tuple[Optional[str], Optional[str]]:
    argv = ["sslscan", *COMMON_SKIPS]
    if check == CHECK_SSLV2V3:
        argv.append("--no-ciphersuites")
    argv.append(target)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout}s"
    except FileNotFoundError:
        return None, "sslscan not found on PATH"
    if proc.returncode != 0 and not proc.stdout:
        err = (proc.stderr or "").strip().splitlines()
        return None, (err[-1] if err else f"sslscan exit {proc.returncode}")
    return proc.stdout, None


def check_sslv2v3(output: str) -> tuple[bool, list, list]:
    """Return (is_vuln, evidence, triggers). Evidence always includes both
    SSLv2 and SSLv3 lines for context in the detail view; triggers is only
    the lines that are 'enabled' (drives VULNERABLE + summary cell).
    """
    proto_lines = []
    triggers = []
    for line in output.splitlines():
        m = PROTO_LINE_RE.match(_strip_ansi(line))
        if not m:
            continue
        enabled = m.group(2).lower() == "enabled"
        raw = line.rstrip()
        proto_lines.append((enabled, raw))
        if enabled:
            triggers.append(raw)
    proto_lines.sort(key=lambda p: not p[0])
    evidence = [l for _, l in proto_lines]
    return bool(triggers), evidence, triggers


def is_weak_cipher(name: str, bits: int) -> bool:
    # < 112 catches NULL (0), EXPORT (40/56), single-DES (56). 3DES is 112-bit
    # effective and belongs to Nessus 42873 (Medium Strength), not 26928 — so
    # don't trip on it via the bit-length rule.
    if bits < 112:
        return True
    for pat in WEAK_NAME_PATTERNS:
        if pat.search(name):
            return True
    return False


def check_weak_ciphers(output: str) -> tuple[bool, list, list]:
    evidence = []
    in_section = False
    for line in output.splitlines():
        plain = _strip_ansi(line)
        stripped_plain = plain.strip()
        if stripped_plain.startswith("Supported Server Cipher"):
            in_section = True
            continue
        if in_section:
            if not stripped_plain:
                if evidence:
                    break
                continue
            if stripped_plain.endswith(":") and "Cipher" not in stripped_plain:
                break
            m = CIPHER_LINE_RE.match(plain)
            if not m:
                continue
            _, _, bits_s, name, _ = m.groups()
            bits = int(bits_s)
            if is_weak_cipher(name, bits):
                evidence.append(line.rstrip())
    return bool(evidence), evidence, list(evidence)


def scan_host(target: str, check: str, timeout: int) -> HostResult:
    output, err = run_sslscan(target, check, timeout)
    if err:
        return HostResult(target=target, status="ERROR", error=err)
    if check == CHECK_SSLV2V3:
        is_vuln, evidence, triggers = check_sslv2v3(output)
    else:
        is_vuln, evidence, triggers = check_weak_ciphers(output)
    status = "VULNERABLE" if is_vuln else "NOT VULNERABLE"
    return HostResult(target=target, status=status, evidence=evidence, triggers=triggers)


def progress_line(done: int, total: int, vuln: int, ok: int, err: int, width: int = 28) -> str:
    pct = done / total if total else 1.0
    filled = int(round(pct * width))
    bar = Color.wrap(Color.CYAN, "█" * filled) + ("░" * (width - filled))
    counts = (
        f"{Color.wrap(Color.RED, str(vuln))} vuln  "
        f"{Color.wrap(Color.GREEN, str(ok))} ok  "
        f"{Color.wrap(Color.YELLOW, str(err))} err"
    )
    return f"  scanning  [{bar}] {done}/{total}   {counts}"


def status_label(status: str) -> str:
    if status == "VULNERABLE":
        return Color.wrap(Color.RED + Color.BOLD, "[VULNERABLE]")
    if status == "NOT VULNERABLE":
        return Color.wrap(Color.GREEN, "[NOT VULNERABLE]")
    return Color.wrap(Color.YELLOW, "[ERROR]")


def print_host_detail(result: HostResult, check: str, max_evidence: int = 10):
    title = CHECK_TITLES[check]
    print(f"{Color.wrap(Color.CYAN, '[*]')} {Color.wrap(Color.BOLD, result.target)}")
    if result.status == "ERROR":
        print(f"    {result.error}")
    else:
        shown = result.evidence[:max_evidence]
        for line in shown:
            print(f"    {_render(line)}")
        extra = len(result.evidence) - len(shown)
        if extra > 0:
            print(f"    ... ({extra} more)")
        if not shown and result.status == "NOT VULNERABLE":
            print("    (no weak ciphers found)")
    print(f"    {status_label(result.status)} {title}")
    print()


def print_summary(results: list, check: str):
    headers = ("TARGET", "STATUS", "EVIDENCE")
    rows = []
    for r in results:
        if r.status == "ERROR":
            ev = r.error or "error"
        elif r.triggers:
            first = r.triggers[0]
            extra = len(r.triggers) - 1
            ev = first + (f"  (+{extra} more)" if extra else "")
        else:
            ev = "—"
        rows.append((r.target, r.status, ev))

    w_target = max(len(headers[0]), max((len(r[0]) for r in rows), default=0))
    w_status = max(len(headers[1]), max((len(r[1]) for r in rows), default=0))

    title = CHECK_TITLES[check]
    print(Color.wrap(Color.BOLD, f"=== Summary: {title} ==="))
    print(f"{headers[0]:<{w_target}}  {headers[1]:<{w_status}}  {headers[2]}")
    print(f"{'-' * w_target}  {'-' * w_status}  {'-' * len(headers[2])}")
    for target, status, ev in rows:
        if status == "VULNERABLE":
            col = Color.RED + Color.BOLD
        elif status == "NOT VULNERABLE":
            col = Color.GREEN
        else:
            col = Color.YELLOW
        status_cell = Color.wrap(col, f"{status:<{w_status}}")
        print(f"{target:<{w_target}}  {status_cell}  {_render(ev)}")


def main():
    parser = argparse.ArgumentParser(
        prog="sslper",
        description="Validate Nessus SSL findings (20007 SSLv2/v3, 26928 weak ciphers) via sslscan.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sslv2v3", action="store_const", dest="check",
                       const=CHECK_SSLV2V3,
                       help="check for SSLv2/SSLv3 protocol support (Nessus 20007)")
    group.add_argument("--weak-ciphers", action="store_const", dest="check",
                       const=CHECK_WEAK,
                       help="check for weak cipher suites (Nessus 26928)")
    parser.add_argument("-f", "--file", help="file of host:port targets (one per line, # comments ok)")
    parser.add_argument("targets", nargs="*", help="host:port targets")
    parser.add_argument("--timeout", type=int, default=30, help="per-host sslscan timeout (default 30s)")
    parser.add_argument("--workers", type=int, default=5, help="concurrent scans (default 5)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        Color.enabled = False

    if not shutil.which("sslscan"):
        print("[!] sslscan not found on PATH. Install with: apt install sslscan", file=sys.stderr)
        sys.exit(2)

    targets = parse_targets(args.targets, args.file)
    if not targets:
        print("[!] no targets supplied. Use -f FILE and/or positional host:port args.", file=sys.stderr)
        parser.print_usage(sys.stderr)
        sys.exit(2)

    results: list = [None] * len(targets)
    counts = {"vuln": 0, "ok": 0, "err": 0}
    lock = threading.Lock()
    is_tty = sys.stdout.isatty()
    term_w = shutil.get_terminal_size((100, 24)).columns

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        future_to_idx = {
            ex.submit(scan_host, t, args.check, args.timeout): i
            for i, t in enumerate(targets)
        }
        done = 0
        for fut in concurrent.futures.as_completed(future_to_idx):
            r = fut.result()
            with lock:
                results[future_to_idx[fut]] = r
                done += 1
                if r.status == "VULNERABLE":
                    counts["vuln"] += 1
                elif r.status == "NOT VULNERABLE":
                    counts["ok"] += 1
                else:
                    counts["err"] += 1
                line = progress_line(done, len(targets),
                                     counts["vuln"], counts["ok"], counts["err"])
                if is_tty:
                    pad = max(0, term_w - _vlen(line) - 1)
                    sys.stdout.write("\r" + line + " " * pad)
                    sys.stdout.flush()
                else:
                    print(line)

    if is_tty:
        sys.stdout.write("\r" + " " * (term_w - 1) + "\r")
        sys.stdout.flush()

    for r in results:
        print_host_detail(r, args.check)
    if len(results) >= 10:
        print_summary(results, args.check)

    any_vuln = any(r.status == "VULNERABLE" for r in results)
    sys.exit(1 if any_vuln else 0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        sys.exit(130)
