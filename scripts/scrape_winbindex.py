import re
import json
from bs4 import BeautifulSoup

# To get the HTML content, just visit winbindex, set it to show 100 entries per page, and then
# in the console, just run copy(document.documentElement.outerHTML)
# that way you store it after JS modifications
# After that, just paste it into a file named http.txt

# The name of your input file is http.txt
input_filename = 'http.txt'
# The name of the file to store the extracted data in JSON format
output_filename = 'extracted-data.json'

def extract_and_store_data(html_file, output_file):
    """
    Extracts download links and related information from an HTML file and stores it in a JSON file.

    Args:
        html_file (str): The path to the input HTML file.
        output_file (str): The path to the output JSON file where the extracted data will be stored.
    """
    try:
        with open(html_file, 'r', encoding='utf-8') as f:
            html_content = f.read()

        soup = BeautifulSoup(html_content, 'html.parser')
        table = soup.find('table', id='winbindex-table')

        if not table:
            print("Error: Could not find the table with id 'winbindex-table'.")
            return

        table_body = table.find('tbody')
        if not table_body:
            print("Error: Could not find the table body.")
            return

        rows = table_body.find_all('tr')
        extracted_data = []

        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 8:
                # Extract SHA256 hash from the 'title' attribute of the first 'a' tag
                hash_link = cols[0].find('a')
                sha256_hash = ''
                if hash_link and 'title' in hash_link.attrs:
                    title_text = hash_link['title']
                    # Use regex to find the SHA256 hash
                    match = re.search(r'([a-fA-F0-9]{64})', title_text)
                    if match:
                        sha256_hash = match.group(1)

                # Extract KB number from the 'title' attribute of the 'abbr' tag
                kb_abbr = cols[2].find('abbr')
                kb_number = kb_abbr.get_text(strip=True) if kb_abbr else 'N/A'

                # Extract File Version
                file_version = cols[4].get_text(strip=True)

                # Extract Download Link
                download_link_tag = cols[7].find('a')
                download_link = download_link_tag['href'] if download_link_tag else 'N/A'

                data = {
                    "Name": "ntoskrnl.exe",
                    "KB": kb_number,
                    "Hash": sha256_hash,
                    "File Version": file_version,
                    "Download Link": download_link
                }
                extracted_data.append(data)

        # Write the extracted data to a JSON file with pretty formatting
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(extracted_data, f, indent=4)

        print(f"Data successfully extracted and stored in JSON file '{output_file}'")

    except FileNotFoundError:
        print(f"Error: The file '{html_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the extraction function
extract_and_store_data(input_filename, output_filename)
