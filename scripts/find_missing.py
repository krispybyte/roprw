import os
import json
import re

def sanitize_filename(text):
    """Remove illegal filename characters."""
    return re.sub(r'[^a-zA-Z0-9.\-_]', '', text)

def get_expected_entries(json_file):
    entries = []
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for entry in data:
                if entry.get("Name", "").lower() != "ntoskrnl.exe":
                    continue

                kb = entry.get("KB", "").strip()
                version = entry.get("File Version", "").strip()
                hash_val = entry.get("Hash", "").strip().lower()

                if not kb or not version:
                    continue

                safe_kb = sanitize_filename(kb)
                safe_version = sanitize_filename(version)
                filename = f"{safe_kb}-{safe_version}.exe"

                entries.append({
                    "filename": filename,
                    "hash": hash_val
                })
    except Exception as e:
        print(f"[!] Error parsing {json_file}: {e}")
    return entries

def get_downloaded_filenames(folder):
    try:
        return set(f for f in os.listdir(folder) if f.lower().endswith('.exe'))
    except FileNotFoundError:
        return None

def find_missing_files():
    json_files = [f for f in os.listdir() if f.endswith('.json')]

    for json_file in sorted(json_files):
        folder_name = os.path.splitext(json_file)[0]
        expected_entries = get_expected_entries(json_file)
        downloaded_files = get_downloaded_filenames(folder_name)

        print(f"\n📂 {folder_name}")

        if downloaded_files is None:
            print("  ❌ Folder not found.")
            continue

        missing = [entry for entry in expected_entries if entry["filename"] not in downloaded_files]

        if not missing:
            print("  ✅ All files downloaded.")
        else:
            print(f"  ⚠️ Missing {len(missing)} file(s):")
            for entry in missing:
                print(f"    - {entry['filename']}")
                print(f"      Hash: {entry['hash']}")

if __name__ == "__main__":
    find_missing_files()
