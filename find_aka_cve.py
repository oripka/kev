#!/usr/bin/env python3
# --- Quick setup / efficient clone instructions ---
# To avoid cloning the full repo history, fetch only the `modules/` folder:
#
#   git clone --depth 1 --filter=blob:none --sparse https://github.com/rapid7/metasploit-framework.git
#   cd metasploit-framework
#   git sparse-checkout set modules
#
# Or, alternatively, export only the folder without Git:
#
#   svn export https://github.com/rapid7/metasploit-framework/trunk/modules modules
#
# Then run this script:
#
#   python3 find_aka_cve.py modules --ts > cveToNameMap.generated.ts
# ----------------------------------------------
"""
find_aka_cve.py

Scan a Metasploit `modules/` tree (exported or sparse-cloned) and extract pairs of
CVE -> AKA (only modules that include explicit AKA entries in a recognizable
literal form). Outputs CSV by default or a TypeScript `cveToNameMap` when
`--ts` is passed.

Usage:
  python3 find_aka_cve.py /path/to/modules > msf_aka_cve.csv
  python3 find_aka_cve.py /path/to/modules --ts > cveToNameMap.generated.ts

Behavior:
 - Only emits rows for files that contain an explicit AKA in a literal form
   commonly used in Metasploit modules, for example:
     "['AKA', 'Heartbleed']"
     "'AKA' => ['Heartbleed']"
     "'AKA': ['Heartbleed']"
 - Gathers all CVE entries found (literal ['CVE','...'] or similar) and pairs
   each CVE with the first AKA discovered in the file.
 - Skips AKA values that look like vendor advisory IDs or end with `.c` (e.g.
   `SA-CORE-2018-002` or `something.c`) based on simple heuristics.
 - Conservative: does not execute Ruby/Python, only uses regex heuristics.

Outputs CSV columns: file,cve,aka
"""

from __future__ import annotations
import argparse
import os
import re
import sys
import csv
from pathlib import Path
from typing import List, Tuple

# Regex to find simple literal entries like ['AKA','name'] or ['CVE','2018-1111']
RE_REF = re.compile(r"""\[\s*(['"])(AKA|CVE)\1\s*,\s*(['"])(.*?)\3\s*\]""", re.IGNORECASE | re.DOTALL)

# Regex to find AKA => [ 'Name', ... ] or 'AKA': [ 'Name', ... ]
# Captures the first quoted string inside the array.
RE_AKA_ARRAY = re.compile(r"['\"]AKA['\"]\s*(?:=>|:)\s*\[\s*(['\"])(.*?)\1", re.IGNORECASE | re.DOTALL)

# Regex to find CVE entries written in many common literal ways (quoted within arrays)
RE_CVE_GENERIC = re.compile(r"CVE[-\s_]*?(\d{4})[-\s_]?([0-9]{4,7})", re.IGNORECASE)

# Heuristic regex to detect vendor advisory-like IDs, e.g. SA-CORE-2018-002
RE_VENDOR_ADVISORY = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{4}-\d{2,}$", re.IGNORECASE)


def normalize_cve(raw: str) -> str:
    """Normalize CVE-like strings to 'CVE-YYYY-NNNN' form (best-effort)."""
    s = raw.strip()
    s = re.sub(r'^\s*CVE[-\s_]*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', '', s)
    m = re.match(r'(\d{4})(\d{4,7})$', s)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    m = re.match(r'(\d{4})[-_]?([0-9]{4,7})$', s)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return s.upper()


def is_aka_filtered(aka: str) -> bool:
    """Return True if the AKA should be excluded based on heuristics.

    Filters:
    - ends with ".c" (case-insensitive)
    - matches vendor advisory pattern like SA-CORE-2018-002
    """
    if not aka:
        return True
    a = aka.strip()
    # ends with .c (common short vendor tag) - case-insensitive
    if a.lower().endswith('.c'):
        return True
    # vendor advisory-like ID
    if RE_VENDOR_ADVISORY.match(a):
        return True
    return False


def extract_from_text(text: str, filepath: str) -> List[Tuple[str, str]]:
    """
    Return list of (cve, aka) found in the given file text. Only returns rows
    if the file contains at least one explicit AKA captured by our heuristics
    OR if we can derive a useful human-friendly name from an inline comment
    that immediately follows a literal CVE array like:

      [ 'CVE', '2017-0143'], # EternalRomance/EternalSynergy - Type confusion ...

    The comment-derived AKA is taken from the portion of the comment before
    the first "-" (if present) and treated as an AKA candidate (subject to
    the same filtering heuristics).
    """
    akas: List[str] = []
    cves: List[str] = []

    # 1) catch ['AKA','Name'] style (array of two elements)
    for m in RE_REF.finditer(text):
        kind = m.group(2).upper()
        val = m.group(4).strip()
        if kind == "AKA":
            akas.append(val)
        elif kind == "CVE":
            # record CVE
            cves.append(normalize_cve(val))
            # attempt to extract a trailing inline comment on the same line
            # e.g. "[ 'CVE', '2017-0143'], # EternalRomance/EternalSynergy - ..."
            # Look from the end of the match to the end of the current line.
            line_end_idx = text.find('\n', m.end())
            if line_end_idx == -1:
                rest_of_line = text[m.end():]
            else:
                rest_of_line = text[m.end():line_end_idx]

            # find comment markers (# or //) and prefer '#'
            comment_idx = -1
            comment_marker = None
            hash_idx = rest_of_line.find('#')
            slash_idx = rest_of_line.find('//')
            if hash_idx != -1:
                comment_idx = hash_idx
                comment_marker = '#'
            elif slash_idx != -1:
                comment_idx = slash_idx
                comment_marker = '//'

            if comment_idx != -1:
                comment = rest_of_line[comment_idx + (1 if comment_marker == '#' else 2):].strip()
                # prefer the part before an explicit dash which often separates
                # a short name from a longer description
                if '-' in comment:
                    comment_name = comment.split('-', 1)[0].strip()
                else:
                    comment_name = comment
                # clean up trailing punctuation
                comment_name = comment_name.rstrip(' ,;:')
                if comment_name:
                    akas.append(comment_name)

    # 2) catch 'AKA' => [ 'Name', ... ] or 'AKA': [ 'Name', ... ] style (including multiline)
    # This pattern extracts everything between [ and ] possibly spanning multiple lines.
    aka_block_re = re.compile(r"['\"]AKA['\"]\s*(?:=>|:)\s*\[(.*?)\]", re.IGNORECASE | re.DOTALL)
    aka_string_re = re.compile(r"['\"]([^'\"]+)['\"]")

    for m in aka_block_re.finditer(text):
        block = m.group(1)
        for s in aka_string_re.findall(block):
            s_clean = s.strip()
            if s_clean:
                akas.append(s_clean)

    # 3) capture any CVE-like tokens elsewhere in the file (best-effort)
    for m in RE_CVE_GENERIC.finditer(text):
        cand = f"CVE-{m.group(1)}-{m.group(2)}"
        if cand not in cves:
            cves.append(cand)

    # If we found no explicit AKA values OR comment-derived AKAs, do NOT emit rows
    if not akas:
        return []

    # filter AKAs according to heuristics, keep first non-filtered AKA
    aka_final = None
    for a in akas:
        if not is_aka_filtered(a):
            aka_final = a
            break

    # if no AKA survived filtering, return nothing
    if not aka_final:
        return []

    # produce rows pairing each CVE with the AKA
    rows: List[Tuple[str, str]] = []
    for c in cves:
        rows.append((c, aka_final))
    return rows


def scan_modules(root: Path) -> List[Tuple[str, str, str]]:
    results: List[Tuple[str, str, str]] = []
    for path in root.rglob("*.rb"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        pairs = extract_from_text(text, str(path))
        for cve, aka in pairs:
            results.append((str(path), cve, aka))
    return results


def make_ts_map(pairs: List[Tuple[str, str, str]]) -> str:
    seen = {}
    out_lines = [
        "// generated from rapid7/metasploit-framework modules",
        "export const cveToNameMap: Record<string,string> = {"
    ]
    for _file, cve, aka in pairs:
        if cve and cve not in seen:
            seen[cve] = aka.replace("'", "\\'")
            out_lines.append(f"  '{cve}': '{seen[cve]}',")
    out_lines.append("};")
    return "\n".join(out_lines)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Extract CVE -> AKA from Metasploit modules (only explicit AKAs)")
    ap.add_argument("modules_dir", help="Path to the modules/ directory to scan")
    ap.add_argument("--ts", action="store_true", help="Output TypeScript map instead of CSV")
    ap.add_argument("--dedup", action="store_true", help="Deduplicate by CVE, keeping first seen")
    args = ap.parse_args(argv[1:])

    root = Path(args.modules_dir)
    if not root.exists() or not root.is_dir():
        print(f"ERROR: {root} is not a directory", file=sys.stderr)
        return 2

    results = scan_modules(root)
    if not results:
        return 0

    if args.ts:
        ts = make_ts_map(results)
        print(ts)
        return 0

    # CSV output (file,cve,aka)
    out_csv = csv.writer(sys.stdout)
    # write header
    out_csv.writerow(["file", "cve", "aka"]) 

    if args.dedup:
        seen = set()
        for f, cve, aka in results:
            if cve in seen:
                continue
            seen.add(cve)
            out_csv.writerow([f, cve, aka])
    else:
        for f, cve, aka in results:
            out_csv.writerow([f, cve, aka])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))