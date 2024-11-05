import requests
import json
import argparse
import re
from bs4 import BeautifulSoup

# Hardcoded API key
API_KEY = "6beeb12-b047-4fc9-a4a9-19d788cf059c"

def check_cves(software_name, version):
    
    url = f"https://nvd.nist.gov/products/cpe/search/results"
    params = {"namingFormat": "2.3", "keyword": f"{software_name} {version}"}
    headers = {
        "apiKey": API_KEY
    }
    response = requests.get(url, headers=headers, params=params)
    
    # Print the request URL and response status code for debugging
    #print(f"Request URL: {url}")
    #print(f"Response Status Code: {response.status_code}")

    if response.status_code == 200:
        try:
            data = response.text
            # Use regex to extract all CPEs from the response
            cpe_pattern = re.compile(r'cpe:(.*?)<')
            cpes = cpe_pattern.findall(data)
            return cpes
        except json.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}")
            print(f"Response content: {response.text}")
            return None
    else:
        # Print an error message if the request failed
        print(f"Error: Failed to retrieve CVEs for {software_name} version {version}. Status Code: {response.status_code}")
        return None
    
def dl_link_PS(product_name):
    url = f"https://packetstormsecurity.com/search/?q={product_name}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', href=True)
            download_links = [f"https://packetstormsecurity.com{result['href']}" for result in results if '/files/download/' in result['href'] and result['href'].endswith('.txt')]
        if not download_links:
            print("No download links found (Packet Storm Security)")
            return download_links
    except requests.RequestException as e:
        print(f"Error fetching download links: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Check if a software has any CVEs.")
    parser.add_argument("json_file", help="Path to the JSON file containing software names and versions")
    args = parser.parse_args()

    with open(args.json_file, 'r') as file:
        software_list = json.load(file)
    
    for software in software_list:
        software_name = software.get("name")
        version = software.get("version")

        if software_name and version:
            cpes = check_cves(software_name, version)
            if cpes:
                print(f"Found {len(cpes)} CPEs for {software_name} version {version}:")
                for cpe in cpes:
                    print(f"{cpe}")
                return cpes
            else:
                print(f"No CPEs found for {software_name} version {version}.")
            dlinks = dl_link_PS(f"{software_name} {version}")
            print(f"DLinks.")
            if dlinks:
                print(f"Found {len(dlinks)} download links for {software_name} version {version}:")
                for dlink in dlinks:
                    print(f"{dlink}")
            else:
                print(f"No download links found for {software_name} version {version}")
        else:
            print(f"Invalid entry in JSON file: {software}")

if __name__ == "__main__":
    main()