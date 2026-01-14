#!/usr/bin/env python

import argparse
import csv
import ipaddress
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit


def _build_parser(show_advanced: bool) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        usage="%(prog)s [INPUT_CSV] [OUTPUT_CSV] [-C COL] [-b BATCH] [-s SECONDS] [-k CACHE]",
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default=None,
        help="Input CSV path (default: data/targets.csv)",
    )
    parser.add_argument(
        "output_csv",
        nargs="?",
        default=None,
        help="Output CSV path (default: <input>.resolved.csv)",
    )
    parser.add_argument(
        "-i",
        "--input",
        default=str(pathlib.Path("data") / "targets.csv"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-C",
        "--col",
        type=int,
        default=None,
        help="1-based column number containing domains (default: auto-detect)",
    )
    parser.add_argument(
        "-c",
        dest="col_deprecated",
        type=int,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-b",
        "--batch-size",
        type=int,
        default=2000,
        help="Domains per puredns batch",
    )
    parser.add_argument(
        "-s",
        "--sleep-seconds",
        type=float,
        default=1.0,
        help="Sleep between batches",
    )
    parser.add_argument(
        "-k",
        "--cache",
        default=None,
        help="Cache resolved domains (one per line)",
    )

    advanced_help = None
    if not show_advanced:
        advanced_help = argparse.SUPPRESS

    parser.add_argument(
        "--help-all",
        action="store_true",
        help="Show all options (advanced)",
    )

    parser.add_argument(
        "-p",
        "--puredns",
        default="puredns",
        help=advanced_help or "puredns binary name or path",
    )
    parser.add_argument(
        "-a",
        "--puredns-args",
        default="",
        help=advanced_help
        or 'Extra args passed to "puredns resolve" (e.g., --resolvers resolvers.txt)',
    )
    parser.add_argument(
        "-d",
        "--resolved-domains-out",
        default=None,
        help=advanced_help or "Write resolved domains list (one per line)",
    )
    return parser


def _parse_args() -> argparse.Namespace:
    if "--help-all" in sys.argv:
        parser = _build_parser(show_advanced=True)
        parser.print_help()
        raise SystemExit(0)

    parser = _build_parser(show_advanced=False)
    return parser.parse_args()


def _read_csv_rows(path: str) -> list[list[str]]:
    with open(path, newline="") as f:
        reader = csv.reader(f)
        return [row for row in reader if row]


_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)


def _normalize_domain_candidate(value: str) -> str | None:
    s = value.strip().strip('"').strip("'")
    if not s:
        return None

    if "://" in s:
        try:
            parts = urlsplit(s)
            if parts.hostname:
                s = parts.hostname
            elif parts.netloc:
                s = parts.netloc
        except Exception:
            pass

    if "/" in s:
        s = s.split("/", 1)[0]

    if ":" in s and not s.startswith("["):
        s = s.split(":", 1)[0]

    s = s.strip().strip(".").lower()
    if not s:
        return None

    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass

    if len(s) > 253:
        return None
    if "." not in s:
        return None
    if ".." in s:
        return None
    if not _DOMAIN_RE.match(s):
        return None
    if s.startswith("-") or s.endswith("-"):
        return None
    return s


def _looks_like_header(row: list[str]) -> bool:
    if not row:
        return False
    tokens = {"domain", "domains", "host", "hostname", "fqdn", "url", "website", "site"}
    lowered = [c.strip().lower() for c in row]
    if any(c in tokens or "domain" in c for c in lowered):
        return True
    if sum(1 for c in row if _normalize_domain_candidate(c)) == 0:
        return True
    return False


def _choose_domain_col(rows: list[list[str]]) -> tuple[int, int]:
    max_cols = max((len(r) for r in rows), default=0)
    if max_cols == 0:
        return 0, 0

    start_idx = 0
    header = rows[0] if rows else []
    if header and _looks_like_header(header) and len(rows) > 1:
        tokens = {"domain", "domains", "host", "hostname", "fqdn"}
        for idx, cell in enumerate(header):
            c = cell.strip().lower()
            if c in tokens or c == "url" or "domain" in c:
                return idx, 1
        start_idx = 1

    best_idx = 0
    best_score = -1
    sample = rows[start_idx : start_idx + 250]
    for col in range(max_cols):
        score = 0
        for row in sample:
            if col >= len(row):
                continue
            if _normalize_domain_candidate(row[col]):
                score += 1
        if score > best_score:
            best_score = score
            best_idx = col
    return best_idx, start_idx


def _extract_domains(rows: list[list[str]], col_idx: int, start_idx: int) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for row in rows[start_idx:]:
        if col_idx >= len(row):
            continue
        domain = _normalize_domain_candidate(row[col_idx])
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains


def _run_puredns_resolve(
    puredns_bin: str, domains: list[str], extra_args: str
) -> set[str]:
    if shutil.which(puredns_bin) is None and not os.path.isabs(puredns_bin):
        raise FileNotFoundError(
            f'"{puredns_bin}" not found in PATH. Install it: go install github.com/d3mondev/puredns/v2@latest'
        )

    puredns_args = shlex.split(extra_args) if extra_args.strip() else []
    has_bin = any(
        a == "--bin" or a.startswith("--bin=")
        for a in puredns_args
    )
    massdns_path = shutil.which("massdns")
    if not has_bin and massdns_path:
        puredns_args.extend(["--bin", massdns_path])

    cmd = [puredns_bin, "resolve", "-q", *puredns_args]

    proc = subprocess.run(
        cmd,
        input=("\n".join(domains) + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        stderr_text = proc.stderr.decode(errors="replace").strip()
        if "unable to execute massdns" in stderr_text and "exec format error" in stderr_text:
            if massdns_path and not has_bin:
                raise RuntimeError(
                    "puredns resolve failed:\n"
                    + stderr_text
                    + "\n\n"
                    + "Detected massdns in PATH but puredns still failed.\n"
                    + f"Tried passing: --bin {massdns_path}\n"
                )
            raise RuntimeError(
                "puredns resolve failed:\n"
                + stderr_text
                + "\n\n"
                + "This usually means massdns is missing or built for the wrong OS/CPU.\n"
                + "Fix:\n"
                + "- Install/compile massdns for your machine and ensure it runs.\n"
                + '- Then rerun with: --help-all and pass e.g. -a "--bin /path/to/massdns"\n'
            )
        raise RuntimeError(
            "puredns resolve failed:\n"
            + stderr_text
        )

    resolved: set[str] = set()
    for line in proc.stdout.decode(errors="replace").splitlines():
        d = line.strip()
        if d:
            resolved.add(d)
    return resolved


def _read_domain_cache(path: str) -> set[str]:
    try:
        with open(path) as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def _append_domain_cache(path: str, domains: set[str]) -> None:
    if not domains:
        return
    parent = pathlib.Path(path).parent
    if str(parent) and not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for d in sorted(domains):
            f.write(d + "\n")


def _chunked(values: list[str], chunk_size: int) -> list[list[str]]:
    if chunk_size <= 0:
        return [values]
    return [values[i : i + chunk_size] for i in range(0, len(values), chunk_size)]


def _write_csv(path: str, rows: list[list[str]]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def _default_output_path(input_path: str) -> str:
    p = pathlib.Path(input_path)
    return str(p.with_name(p.name + ".resolved.csv"))


def main() -> int:
    args = _parse_args()

    if args.col_deprecated is not None:
        args.col = args.col_deprecated

    input_csv = args.input_csv or args.input
    output_csv = args.output_csv or args.output

    rows = _read_csv_rows(input_csv)
    if not rows:
        print("error: input CSV is empty", file=sys.stderr)
        return 2

    start_idx = 0
    if args.col is not None:
        if args.col < 1:
            print("error: -C/--col must be >= 1", file=sys.stderr)
            return 2
        col_idx = args.col - 1
        if _looks_like_header(rows[0]) and len(rows) > 1:
            start_idx = 1
    else:
        col_idx, start_idx = _choose_domain_col(rows)

    domains = _extract_domains(rows, col_idx, start_idx)
    if not domains:
        print("error: no domains found in input CSV", file=sys.stderr)
        return 2

    if args.batch_size < 1:
        print("error: --batch-size must be >= 1", file=sys.stderr)
        return 2
    if args.sleep_seconds < 0:
        print("error: --sleep-seconds must be >= 0", file=sys.stderr)
        return 2

    cached_resolved: set[str] = set()
    if args.cache:
        cached_resolved = _read_domain_cache(args.cache)

    try:
        to_query = [d for d in domains if d not in cached_resolved]
        resolved = set(cached_resolved)

        batches = _chunked(to_query, args.batch_size)
        for idx, batch in enumerate(batches):
            if not batch:
                continue
            resolved.update(_run_puredns_resolve(args.puredns, batch, args.puredns_args))
            if idx != len(batches) - 1 and args.sleep_seconds > 0:
                time.sleep(args.sleep_seconds)
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 2

    filtered_rows: list[list[str]] = []
    for row in rows:
        if col_idx >= len(row):
            continue
        d = _normalize_domain_candidate(row[col_idx])
        if d and d in resolved:
            filtered_rows.append(row)

    out_path = output_csv or _default_output_path(input_csv)
    _write_csv(out_path, filtered_rows)

    resolved_out_path = args.resolved_domains_out
    if not resolved_out_path:
        resolved_out_path = str(pathlib.Path(out_path).with_suffix(".txt"))
    with open(resolved_out_path, "w") as f:
        for d in sorted(resolved):
            f.write(d + "\n")

    if args.cache:
        _append_domain_cache(args.cache, resolved - cached_resolved)

    print(
        f"input_domains={len(domains)} resolved={len(resolved)} output_rows={len(filtered_rows)} output={out_path} resolved_domains_out={resolved_out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
