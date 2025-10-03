#!/usr/bin/env python3
import os
import json
import re
import subprocess
import shlex
from pathlib import Path

# --------------------
# Configuration
# --------------------
ROPPER_CMD = r"C:\Users\krispy\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts\ropper.exe"             # The ropper executable (must be in PATH)
ROPPER_NO_COLOR_FLAG = "--nocolor"  # common flag; if not supported ropper output will be sanitized anyway
TIMEOUT_SECONDS = 300            # per-run timeout for ropper
# --------------------

ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[mKHFJsu]')

def sanitize_filename(text: str) -> str:
    """Make a safe filename by removing characters that might be problematic in filenames."""
    # Keep letters, numbers, dots, hyphen, underscore
    return re.sub(r'[^A-Za-z0-9.\-_]', '', text)

def find_json_files():
    return sorted([p for p in os.listdir() if p.endswith('.json')])

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def expected_entries_from_json(json_path):
    """
    Return list of dicts: { filename: <KB-version.exe>, kb:..., version:..., hash:... }
    Only entries where Name == ntoskrnl.exe are returned.
    """
    out = []
    try:
        data = load_json(json_path)
    except Exception as e:
        print(f"[!] Failed to parse JSON {json_path}: {e}")
        return out

    for entry in data:
        if entry.get("Name", "").lower() != "ntoskrnl.exe":
            continue
        kb = entry.get("KB", "").strip()
        version = entry.get("File Version", "").strip()
        hash_val = entry.get("Hash", "").strip().lower()
        if not kb or not version:
            # skip incomplete entries
            continue
        safe_kb = sanitize_filename(kb)
        safe_ver = sanitize_filename(version)
        filename = f"{safe_kb}-{safe_ver}.exe"
        out.append({
            "filename": filename,
            "kb": kb,
            "version": version,
            "hash": hash_val
        })
    return out

def strip_ansi(s: str) -> str:
    """Remove ANSI escape sequences from a string."""
    return ANSI_ESCAPE_RE.sub('', s)

def run_ropper_on_file(binary_path: str) -> str:
    """
    Runs ropper on binary_path and returns its stdout (with ANSI sequences stripped).
    Tries to pass a no-color flag; if that fails, still captures output and strips ANSI codes.
    """
    attempt_cmds = [
        [ROPPER_CMD, "-f", binary_path, ROPPER_NO_COLOR_FLAG],  # preferred (if ropper supports)
        [ROPPER_CMD, "-f", binary_path]                         # fallback
    ]

    last_exc = None
    for cmd in attempt_cmds:
        try:
            # If any element is empty (e.g. ROPPER_NO_COLOR_FLAG == ""), filter it out
            cmd = [c for c in cmd if c]
            # Run and capture stdout
            completed = subprocess.run(cmd,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True,
                                       timeout=TIMEOUT_SECONDS)
            # Prefer stdout; if empty maybe stderr contains info (some ropper versions print to stderr)
            output = completed.stdout if completed.stdout else completed.stderr
            return strip_ansi(output)
        except FileNotFoundError as e:
            last_exc = e
            break  # ropper not installed
        except subprocess.TimeoutExpired as e:
            last_exc = e
            print(f"[!] ropper timed out for {binary_path}")
            break
        except Exception as e:
            last_exc = e
            # try next variant
            continue

    # If we get here, ropper failed to run
    raise RuntimeError(f"failed to run ropper (last error: {last_exc})")

def ensure_gadgets_dir(parent_dir: str) -> str:
    gadgets_dir = os.path.join(parent_dir, "Gadgets")
    os.makedirs(gadgets_dir, exist_ok=True)
    return gadgets_dir

def main():
    json_files = find_json_files()
    if not json_files:
        print("No .json files found in current directory.")
        return

    print(f"Found {len(json_files)} json file(s).")
    for j in json_files:
        parent_dir = os.path.splitext(j)[0]  # e.g., Windows10-22h2
        expected = expected_entries_from_json(j)
        if not expected:
            print(f"\n[{parent_dir}] No ntoskrnl.exe entries found; skipping.")
            continue

        gadgets_dir = ensure_gadgets_dir(parent_dir)
        print(f"\n[{parent_dir}] Generating gadgets for {len(expected)} file(s). Output dir: {gadgets_dir}")

        for entry in expected:
            exe_name = entry["filename"]
            exe_path = os.path.join(parent_dir, exe_name)
            out_name = f"{os.path.splitext(exe_name)[0]}.gadgets.txt"
            out_path = os.path.join(gadgets_dir, out_name)

            if not os.path.isfile(exe_path):
                print(f"  - Missing binary: {exe_path}  (skipping)")
                continue

            # If gadget file already exists, skip (user did not ask to regenerate)
            if os.path.isfile(out_path):
                print(f"  - Gadget file exists: {out_name} (skipping)")
                continue

            print(f"  - Running ropper on: {exe_name} ...", end=' ', flush=True)
            try:
                ropper_output = run_ropper_on_file(exe_path)
            except RuntimeError as e:
                print(f"\n    [ERROR] {e}")
                continue
            except Exception as e:
                print(f"\n    [ERROR] unexpected error: {e}")
                continue

            # Save output without color (we already stripped ANSI sequences)
            try:
                with open(out_path, 'w', encoding='utf-8') as fo:
                    fo.write(ropper_output)
                print("done.")
            except Exception as e:
                print(f"\n    [ERROR] Failed to write {out_path}: {e}")

    print("\nAll done.")

if __name__ == "__main__":
    main()
