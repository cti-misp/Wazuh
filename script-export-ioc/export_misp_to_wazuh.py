import sys
import urllib3
import concurrent.futures
from pymisp import PyMISP

# Disable warnings for insecure requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
MISP_URL = "https://{IP-MISP}/" #<-- change this --> 
API_KEY = "{API-Key}" #<-- change  this --> 
OUTPUT_FILE = "misp_sha256"
VERIFY_SSL = False
# Batch size for pagination. 
# Recommended: 1000. 
# Increasing this (e.g. 2000-5000) may improve speed but risks server-side timeouts or higher memory usage.
BATCH_SIZE = 1000
MAX_WORKERS = 5 # Number of parallel threads

def format_wazuh_entry(attr):
    """Formats a single MISP attribute to Wazuh CDB format."""
    value = attr.get("value")
    event_id = attr.get("event_id")
    # Wazuh CDB format: key:value
    if value:
        return f"{value}:Event_{event_id}"
    return None

def fetch_page_attributes(misp_instance, page, limit):
    """Fetches a single page of attributes."""
    print(f"Fetching page {page}...")
    try:
        response = misp_instance.search(
            controller='attributes',
            type_attribute='sha256', # type attribute
            to_ids=1, # only ids
            tags='NCSA', # tag name
            publish_timestamp='90d',  # 90 days
            return_format='json', # format response
            limit=limit,
            page=page
        )
        
        if isinstance(response, dict) and 'response' in response:
            return response['response'].get('Attribute', [])
        elif isinstance(response, list):
            return response
        elif isinstance(response, dict):
             return response.get('Attribute', [])
        return []
    except Exception as e:
        print(f"Error fetching page {page}: {e}")
        return []

def fetch_and_export_attributes():
    print(f"Connecting to {MISP_URL} with {MAX_WORKERS} workers...")
    total_entries = 0
    misp = PyMISP(MISP_URL, API_KEY, ssl=VERIFY_SSL) # Shared instance (PyMISP is generally thread-safe for reads)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Initial batch of tasks
            future_to_page = {
                executor.submit(fetch_page_attributes, misp, page, BATCH_SIZE): page 
                for page in range(1, MAX_WORKERS + 1)
            }
            
            next_page_to_submit = MAX_WORKERS + 1
            stop_submission = False

            while future_to_page:
                # Wait for at least one future to complete
                done, _ = concurrent.futures.wait(
                    future_to_page, return_when=concurrent.futures.FIRST_COMPLETED
                )

                for future in done:
                    page = future_to_page.pop(future)
                    try:
                        attributes = future.result()
                        count = 0
                        for attr in attributes:
                            entry = format_wazuh_entry(attr)
                            if entry:
                                f.write(f"{entry}\n")
                                count += 1
                        total_entries += count
                        
                        # Logic to continue or stop
                        # If we got less than BATCH_SIZE, it implies end of data (or empty page)
                        # So we shouldn't submit new pages deeply beyond this, 
                        # BUT since tasks complete out of order, strictly stopping on *any* < limit is safer 
                        # to ensure we don't hammer the server for page 1000 if page 5 was empty.
                        if len(attributes) < BATCH_SIZE:
                            stop_submission = True
                        
                        if not stop_submission:
                            # Submit next page
                            new_future = executor.submit(
                                fetch_page_attributes, misp, next_page_to_submit, BATCH_SIZE
                            )
                            future_to_page[new_future] = next_page_to_submit
                            next_page_to_submit += 1
                            
                    except Exception as exc:
                        print(f"Page {page} generated an exception: {exc}")

    print(f"Done. Successfully wrote {total_entries} entries to {OUTPUT_FILE}")

def main():
    fetch_and_export_attributes()

if __name__ == "__main__":
    main()
