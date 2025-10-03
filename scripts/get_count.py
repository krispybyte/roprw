import os
import json
from time import sleep

def count_expected_files(json_file):
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Only count entries for ntoskrnl.exe (or all if you prefer)
            return sum(1 for entry in data if entry.get("Name", "").lower() == "ntoskrnl.exe")
    except Exception as e:
        print(f"[!] Error reading {json_file}: {e}")
        return 0

def count_downloaded_files(folder):
    try:
        return len([f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))])
    except FileNotFoundError:
        return 0

def show_progress_bar(current, total, width=40):
    if total == 0:
        bar = '[ No data ]'
    else:
        progress = current / total
        filled = int(progress * width)
        bar = '[' + '#' * filled + '-' * (width - filled) + f'] {current}/{total} ({progress*100:.1f}%)'
    return bar

def monitor_download_progress():
    json_files = [f for f in os.listdir() if f.endswith('.json')]

    print("\n🔍 Monitoring Download Progress...\n")

    for json_file in sorted(json_files):
        folder_name = os.path.splitext(json_file)[0]
        expected_count = count_expected_files(json_file)
        downloaded_count = count_downloaded_files(folder_name)

        bar = show_progress_bar(downloaded_count, expected_count)
        print(f"{folder_name.ljust(30)} {bar}")

if __name__ == "__main__":
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        monitor_download_progress()
        sleep(1)

