import os
import json
import requests
import hashlib
import re

def sanitize_filename(name):
    # Remove or replace invalid Windows filename characters
    return re.sub(r'[<>:"/\\|?*+()]', '', name)

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def download_file(url, dest_path):
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return True
    except requests.RequestException as e:
        print(f"  [✗] Download failed: {e}")
        return False

def download_ntoskrnl_files():
    json_files = [f for f in os.listdir() if f.endswith('.json')]

    for file in json_files:
        folder_name = os.path.splitext(file)[0]

        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        print(f"\n📁 Processing {file}")

        with open(file, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"  [!] Invalid JSON in {file}, skipping.")
                continue

        for entry in data:
            if entry.get("Name", "").lower() != "ntoskrnl.exe":
                continue

            kb = entry.get("KB")
            version = entry.get("File Version")
            url = entry.get("Download Link")
            expected_hash = entry.get("Hash", "").lower()

            if not all([kb, version, url]):
                print("  [!] Incomplete entry, skipping.")
                continue

            sanitized_kb = sanitize_filename(kb)
            sanitized_version = sanitize_filename(version)
            filename = f"{sanitized_kb}-{sanitized_version}.exe"
            filepath = os.path.join(folder_name, filename)

            if os.path.exists(filepath):
                actual_hash = calculate_sha256(filepath)
                if actual_hash == expected_hash:
                    print(f"  [✓] Exists and verified: {filename}")
                    continue
                else:
                    print(f"  [↻] Hash mismatch for {filename}, re-downloading...")

            print(f"  [↓] Downloading: {filename}")
            success = download_file(url, filepath)

            if success:
                actual_hash = calculate_sha256(filepath)
                if actual_hash == expected_hash:
                    print(f"  [✔] Downloaded and verified: {filename}")
                else:
                    print(f"  [✗] Hash mismatch after download: {filename} (but file kept)")
            else:
                print(f"  [✗] Failed to download: {filename}")

if __name__ == "__main__":
    download_ntoskrnl_files()
