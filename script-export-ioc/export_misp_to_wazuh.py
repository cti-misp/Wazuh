import sys
import urllib3
from pymisp import PyMISP

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
MISP_URL = "https://{IP-MISP}/" #<-- change this --> 
API_KEY = "{API-Keys}" #<-- change  this --> 
OUTPUT_FILE = "misp_sha256"
VERIFY_SSL = False

def fetch_misp_attributes():
    print(f"Connecting to {MISP_URL}...")
    all_attributes = []
    page = 1
    limit = 1000  # Fetch in chunks to avoid server timeouts

    try:
        misp = PyMISP(MISP_URL, API_KEY, ssl=VERIFY_SSL)
        
        while True:
            print(f"Fetching page {page}...")
            # Search for attributes with pagination
            response = misp.search(
                controller='attributes',
                type_attribute='sha256',
                to_ids=1,
                publish_timestamp='90d',  # 90 days
                return_format='json',
                limit=limit,
                page=page
            )
            
            # Extract attributes from response
            current_page_attributes = []
            if isinstance(response, dict) and 'response' in response:
                current_page_attributes = response['response'].get('Attribute', [])
            elif isinstance(response, list):
                current_page_attributes = response
            elif isinstance(response, dict):
                 current_page_attributes = response.get('Attribute', [])

            if not current_page_attributes:
                break
                
            all_attributes.extend(current_page_attributes)
            
            # If we got fewer than the limit, this is the last page
            if len(current_page_attributes) < limit:
                break
                
            page += 1
            
        return all_attributes
    except Exception as e:
        print(f"Error fetching data from MISP: {e}")
        sys.exit(1)

def format_for_wazuh(data):
    cdb_entries = []
    # PyMISP search returns a list of dictionaries directly or a dict with 'response' key depending on version/endpoint
    # Handling both just in case, though search() usually returns the list of attributes directly if return_format='json'
    
    attributes = []
    if isinstance(data, dict) and 'response' in data:
        attributes = data['response'].get('Attribute', [])
    elif isinstance(data, list):
        attributes = data
    else:
        # Fallback or unexpected format
        attributes = data.get('Attribute', []) if isinstance(data, dict) else []

    print(f"Found {len(attributes)} attributes.")
    
    for attr in attributes:
        # PyMISP returns dicts, keys might differ slightly depending on expansion, but 'value' is standard
        value = attr.get("value")
        event_id = attr.get("event_id")
        comment = attr.get("comment", "")
        
        if value:
            # Wazuh CDB format: key:value
            entry = f"{value}:Event_{event_id}"
            cdb_entries.append(entry)
            
    return cdb_entries

def save_to_file(entries, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for entry in entries:
                f.write(f"{entry}\n")
        print(f"Successfully wrote {len(entries)} entries to {filename}")
    except IOError as e:
        print(f"Error writing to file: {e}")

def main():
    data = fetch_misp_attributes()
    entries = format_for_wazuh(data)
    if entries:
        save_to_file(entries, OUTPUT_FILE)
    else:
        print("No entries found to export.")

if __name__ == "__main__":
    main()
