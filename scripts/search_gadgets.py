
from __future__ import annotations
import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict

def find_release_dirs(base_dir: Path) -> List[Path]:
    """Return sorted list of immediate subdirectories in base_dir."""
    dirs = [p for p in sorted(base_dir.iterdir()) if p.is_dir()]
    return dirs

def find_gadget_files(release_dir: Path) -> List[Path]:
    """Find all *.gadgets.txt files under release_dir/Gadgets/."""
    gadgets_dir = release_dir / "Gadgets"
    if not gadgets_dir.exists() or not gadgets_dir.is_dir():
        return []
    return sorted(gadgets_dir.glob("*.gadgets.txt"))

def compile_pattern(query: str, regex: bool, ignore_case: bool):
    flags = re.MULTILINE
    if ignore_case:
        flags |= re.IGNORECASE
    if regex:
        try:
            return re.compile(query, flags)
        except re.error as e:
            print(f"[ERROR] invalid regular expression: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        # escape the query for a literal search
        return re.compile(re.escape(query), flags)

def search_file_for_pattern(path: Path, pattern: re.Pattern, context: int = 0) -> List[Dict]:
    """
    Search a file for pattern. Return list of matches.
    Each match dict: {'line_no': int, 'line': str, 'context_before': [str], 'context_after': [str]}
    """
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        return [{"error": f"failed to read file: {e}"}]

    lines = text.splitlines()
    matches = []

    for i, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, i - context)
            end = min(len(lines), i + context + 1)
            matches.append({
                "line_no": i + 1,
                "line": line,
                "context_before": lines[start:i],
                "context_after": lines[i+1:end]
            })
    return matches

def human_path(p: Path) -> str:
    return str(p)

def print_match(path: Path, match: Dict, highlight: bool = False):
    """Print a single match with context."""
    # No color highlighting by default (user requested no color-preservation)
    for bline in match.get("context_before", []):
        print(f"    {bline}")
    print(f"  -> {match['line_no']:5d}: {match['line']}")
    for aline in match.get("context_after", []):
        print(f"    {aline}")

def main(argv=None):
    ap = argparse.ArgumentParser(description="Search gadget files under each release's Gadgets/ folder.")
    ap.add_argument("query", help="Gadget string to search for (literal by default). Example: \"push rcx; pop rsp;\"")
    ap.add_argument("--base-dir", "-b",
                    default=r"C:\Users\krispy\Documents\roprw\scripts",
                    help="Base directory containing release folders (default matches your path).")
    ap.add_argument("--regex", "-r", action="store_true", help="Treat query as a regular expression.")
    ap.add_argument("--ignore-case", "-i", action="store_true", help="Case-insensitive search.")
    ap.add_argument("--context", "-c", type=int, default=0, help="Number of context lines to show before/after each match.")
    ap.add_argument("--show-missing-only", action="store_true", help="Only print items where the gadget is missing.")
    ap.add_argument("--summary-only", action="store_true", help="Print a compact summary at the end.")
    ap.add_argument("--max-per-file", type=int, default=50, help="Max matches shown per file (0 = show all).")
    ap.add_argument("--version", "-v", help="Scan only a specific version folder (e.g. Windows11-22h2)")
    args = ap.parse_args(argv)

    base_dir = Path(args.base_dir).expanduser()
    if not base_dir.exists() or not base_dir.is_dir():
        print(f"[ERROR] base directory does not exist or is not a directory: {base_dir}", file=sys.stderr)
        sys.exit(1)

    pattern = compile_pattern(args.query, regex=args.regex, ignore_case=args.ignore_case)

    # Support filtering by version
    if args.version:
        release_dirs = [base_dir / args.version]
        if not release_dirs[0].exists():
            print(f"[ERROR] Specified version folder does not exist: {release_dirs[0]}")
            sys.exit(1)
    else:
        release_dirs = find_release_dirs(base_dir)

    if not release_dirs:
        print(f"No release directories found in {base_dir}")
        return

    overall_summary = {}  # release -> { 'files_total':n, 'files_with_match': [file1,..], 'files_without_match':[...], 'gadgets_dir_missing':bool }

    for rel in release_dirs:
        gadget_files = find_gadget_files(rel)
        rel_summary = {
            "gadgets_dir_missing": False,
            "files_total": 0,
            "files_with_match": [],
            "files_without_match": []
        }

        if not gadget_files:
            # no Gadgets directory or no gadget files
            gadgets_dir = rel / "Gadgets"
            if not gadgets_dir.exists():
                rel_summary["gadgets_dir_missing"] = True
                overall_summary[str(rel)] = rel_summary
                if not args.summary_only:
                    print(f"\n[ {rel.name} ]  -> Gadgets/ folder missing.")
                continue
            else:
                # Gadgets exists but no files
                rel_summary["files_total"] = 0
                overall_summary[str(rel)] = rel_summary
                if not args.summary_only:
                    print(f"\n[ {rel.name} ]  -> Gadgets/ folder empty (no *.gadgets.txt files).")
                continue

        rel_summary["files_total"] = len(gadget_files)

        if not args.summary_only:
            print(f"\n[ {rel.name} ]  Searching {len(gadget_files)} gadget file(s) in {rel / 'Gadgets'}")

        for gf in gadget_files:
            matches = search_file_for_pattern(gf, pattern, context=args.context)
            # if read error
            if matches and isinstance(matches[0], dict) and "error" in matches[0]:
                # treat as missing but report error
                rel_summary["files_without_match"].append((gf, matches[0]["error"]))
                if not args.summary_only and not args.show_missing_only:
                    print(f"  - {gf.name}: ERROR reading file: {matches[0]['error']}")
                continue

            if not matches:
                rel_summary["files_without_match"].append((gf, None))
                if not args.summary_only and args.show_missing_only:
                    print(f"  - MISSING in {gf.name}")
                elif not args.summary_only and not args.show_missing_only:
                    # keep behavior: don't print every missing unless requested — but user wanted to print where missing, so print
                    print(f"  - {gf.name}: no match")
            else:
                rel_summary["files_with_match"].append((gf, matches))
                if not args.summary_only and not args.show_missing_only:
                    print(f"  - {gf.name}: {len(matches)} match(es)")
                    shown = 0
                    for m in matches:
                        if args.max_per_file and shown >= args.max_per_file:
                            print(f"    ... (more matches hidden, increase --max-per-file)")
                            break
                        print_match(gf, m)
                        shown += 1

        overall_summary[str(rel)] = rel_summary

    # Print compact summary if requested or always print missing files summary
    print("\n\n===== SUMMARY =====\n")
    for rel_name, s in overall_summary.items():
        relp = Path(rel_name)
        print(f"{relp.name}: ", end='')
        if s.get("gadgets_dir_missing"):
            print("Gadgets/ missing")
            continue
        total = s.get("files_total", 0)
        with_match = len(s.get("files_with_match", []))
        without = len(s.get("files_without_match", []))
        print(f"{with_match}/{total} files contain the gadget, {without} do not.")
        if without:
            print("  Missing in:")
            for gf, err in s["files_without_match"]:
                if err:
                    print(f"    - {gf.name} (ERROR: {err})")
                else:
                    print(f"    - {gf.name}")
        # small spacer
        print()

if __name__ == "__main__":
    main()
