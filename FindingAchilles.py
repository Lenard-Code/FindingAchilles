"""
FindingAchilles.py
==================
A script to check if a software has any CVEs (Common Vulnerabilities and Exposures).

Dependencies:
-------------
- requests
- json
- argparse
- re
- time
- BeautifulSoup (from bs4)
- pyExploitDb

Usage:
------
Run the script with the required arguments:
    python FindingAchilles.py --input <path_to_input_json> [--output <path_to_output_file>] [--microsoft]

Options:
--------
--input, -i      Path to the JSON file containing software names and versions (required).
--output, -o     Path to the output text file (optional).
--microsoft      Ignore all Microsoft publisher applications (optional).

Example:
--------
    python FindingAchilles.py --input software_list.json --output results.txt --microsoft

"""

import requests
import json
import argparse
import re
import time
from bs4 import BeautifulSoup
from pyExploitDb import PyExploitDb
import nvdlib

# Hardcoded API key
API_KEY = "NVD-API-KEY"
bearer_token = "FROM-CVEDETAILS.COM"

def display_banner():
    banner = """
/= | |\| |) | |\| (_, /\ ( |-| | |_ |_ [- _\~  
                                                                                                             
    Relax... Its running... wait you bot.
    """
    print(banner)

def fetch_cves_by_cpe(cpe):
    results = []
    try:
        response = nvdlib.searchCVE(cpeName=cpe)
        for cve in response:
            cve_data = {
                'CVE ID': cve.id,
                #'Description': cve.descriptions[0].value if cve.descriptions else 'No description available',
                #'Published Date': cve.publishedDate,
                #'Last Modified Date': cve.lastModifiedDate,
                #'CVSS v3.1 Base Score': cve.v3_1.get('baseScore') if cve.v3_1 else 'N/A',
                #'CVSS v2.0 Base Score': cve.v2.get('baseScore') if cve.v2 else 'N/A',
                'Link': f'https://nvd.nist.gov/vuln/detail/{cve.id}'
            }
            results.append(cve_data)
    except Exception as e:
        print(f"Error fetching CVEs for CPE {cpe}: \n --- {e}")
    return results

def check_cves(software_name, version):
    cpes = []
    cve_details = []
    
    # Fetch CPEs using existing method
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={software_name}%20{version}"
    headers = {
        "apiKey": API_KEY
        }
    response = requests.request("GET", url, headers=headers)
    if response.status_code == 200:
        try:
            data = response.json()
            cpe_ids = set()
            cpe_nums = set()
            for product in data.get("products", []):
                cpe = product.get("cpe", {})
                cpe_num = cpe.get("cpeName")
                if cpe_num:
                    cpe_nums.add(cpe_num)
                cpe_name_id = cpe.get("cpeNameId")
                if cpe_name_id:
                    cpe_ids.add(cpe_name_id)
            return list(cpe_nums)
        except json.JSONDecodeError as e:
            print(f"JSONDecodeError: {e}")
            print(f"Response content: {response.text}")
            return None
    else:
        print(f"Error: Failed to retrieve CVEs for {software_name} version {version}. Status Code: {response.status_code}")
        return None
    
def dl_link_PS(product_name):
    url = f"https://packetstormsecurity.com/search/?q={product_name}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', href=True)
            download_links = [f"https://packetstormsecurity.com{result['href']}" for result in results if '/files/download/' in result['href'] and not result['href'].endswith('.txt')]
            #if not download_links:
                #print(f"[+] No download links found for {product_name} (Packet Storm Security)")
            return download_links
    except requests.RequestException as e:
        print(f"Error fetching download links: {e}")
        return []

def search_marc_info(search_term):
    url = f"https://marc.info/?l=full-disclosure&s={search_term}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            pre_tag = soup.find('pre')
            if pre_tag:
                post_links = pre_tag.find_all('a', string=lambda text: text is not None and "full-disc" not in text)
                results = [{"Name": link.get_text(strip=True), "Link": "https://marc.info" + link['href']} for link in post_links]
                if results:
                    return results
            return []
        else:
            print(f"Failed to retrieve the web page. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error fetching Marc.Info data: {e}")
    return []

def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    all_cve_details = []
    headers = {
        "apiKey": API_KEY
    }
    for cpe_string in [cpe_string]:
        time.sleep(1)
        cve_query_string = ":".join(cpe_string.split(":")[1:5])
        url = f"{base_url}cpeName={cpe_string}"
        #print(f"Querying: {url}")

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if response.status_code == 200:
                for cve_item in data.get("vulnerabilities", []):
                    cve_id = cve_item.get("cve", {}).get("id", "N/A")
                    description_text = cve_item.get("cve", {}).get("descriptions", [{}])[0].get("value", "No description")
                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    weaknesses = [desc.get("value", "No description") for problem_type in cve_item.get("cve", {}).get("weaknesses", []) for desc in problem_type.get("description", [])]

                    pEdb = PyExploitDb()
                    pEdb.debug = False
                    pEdb.openFile()

                    try:
                        exploit_status = "Public Exploit Found over Exploit-DB" if pEdb.searchCve(cve_id) else "No Public Exploit Found over Exploit-DB"
                    except ValueError as e:
                        exploit_status = "Error processing Exploit-DB response."

                    snyk_short_name = synk_db(cve_id)

                    all_cve_details.append({
                        "CVE ID": cve_id,
                        "Short Name": snyk_short_name,
                        "Description": description_text,
                        "Weaknesses": ", ".join(weaknesses),
                        "Link": link,
                        "Exploit Status": exploit_status
                    })
            else:
                return (f"Failed to retrieve NVD CVE details for CPE: {cpe_string}. Status code: {response.status_code}")
                continue
        except requests.RequestException as e:
            #print(response.status_code)
            continue
        except json.JSONDecodeError:
            error_return = f"Error decoding JSON for CPE: {cpe_string}. Skipping."
            return error_return

    return all_cve_details

def fetch_github_urls(cve_id):
    api_url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            if "pocs" in data and data["pocs"]:
                return [poc["html_url"] for poc in data["pocs"]]
    except requests.RequestException as e:
        print(f"Error fetching GitHub URLs: {e}")
    return []

def synk_db(cve_id):
    try:
        res = requests.get(f"https://security.snyk.io/vuln/?search={cve_id}")
        a_tag_pattern = r'data-snyk-test="vuln table title".*>([^"]+)<!----><!---->'
        a_tag_matches = re.findall(a_tag_pattern, res.text)
        if a_tag_matches:
            return a_tag_matches[0].strip()
    except requests.RequestException as e:
        print(f"Error fetching Snyk data: {e}")
    return None

def extract_version(value):
    version_pattern = re.compile(r'(\d+\.\d+(\.\d+)*(\.\d+)*)')
    match = version_pattern.search(value)
    if match:
        return match.group(0)
    return None

def sanitize_version(version):
    if version is None:
        return None
    return re.sub(r'[^0-9.]', '', version)
#Adjust as needed, simple list to get started
def normalize_software_name(name):
    if "Python" in name:
        return "Python"
    if "Wix" in name:
        return "Wix"
    if "ASUS" in name:
        return "ASUS"
    if "SEGGER Microcontroller GmbH" in name:
        return "Segger Microcontroller GmbH"
    if "Windows Driver Package - SEGGER" in name:
        return "Segger"
    return name

def search_cves_by_cpe(cpe, bearer_token):
    url = "https://www.cvedetails.com/api/v1/vulnerability/list-by-cpe?"
    headers = {
        'Authorization': f'Bearer {bearer_token}',
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.0.0'
    }
    params = {
        'cpe': cpe
    }
    time.sleep(1)
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        cves = response.json()
        return cves.get('results', [])
    except requests.RequestException as e:
        print(f"Error fetching CVEs (CVEDetails) for CPE {cpe}: \n --- {e}")
        print(f"Trying nvdlib for {cpe}")
        fetch_cves_by_cpe(cpe)
        return None
    
def format_cve_details(cve_details):
    formatted_details = []
    for cve in cve_details:
        formatted_details.append(f"CVE ID: {cve['cveId']}")
        formatted_details.append(f"Summary: {cve['summary']}")
        #formatted_details.append(f"Publish Date: {cve['publishDate']}")
        #formatted_details.append(f"Update Date: {cve['updateDate']}")
        #formatted_details.append(f"Max CVSS Base Score: {cve['maxCvssBaseScore']}")
        #formatted_details.append(f"Max CVSS Exploitability Score: {cve['maxCvssExploitabilityScore']}")
        #formatted_details.append(f"Max CVSS Impact Score: {cve['maxCvssImpactScore']}")
        #formatted_details.append("-----")
    return '\n'.join(formatted_details)
    
def main():
    parser = argparse.ArgumentParser(description="Check if a software has any CVEs.")
    parser.add_argument("--input", "-i", required=True, help="Path to the JSON file containing software names and versions")
    parser.add_argument("--output", "-o", help="Path to the output text file")
    parser.add_argument("--microsoft", action="store_true", help="Ignore all Microsoft publisher applications")
    args = parser.parse_args()

    display_banner()
    # Initialize software_list as an empty list
    software_list = []    
    with open(args.input, 'r', encoding='latin-1') as file:
        software_list = json.load(file)
    
    results = []
    seen = set()
    for software in software_list:
        unique_cve_ids = set()
        cve_details_list = []
        software_name = normalize_software_name(software.get("DisplayName"))
        version = software.get("DisplayVersion")
        publisher = software.get("Publisher")
    
        if version:
            version = extract_version(version)
            version = sanitize_version(version)
        
        if args.microsoft and publisher in ["Microsoft Corporation", "Microsoft", "Microsoft Corporations"]:
            continue
    
        unique_key = (software_name, version)
        if unique_key in seen:
            continue
        seen.add(unique_key)
    
        if software_name and version:
            
            cpes = check_cves(software_name, version)
            if cpes:
                results.append(f"\n[!] Found {len(cpes)} CPEs for {software_name} version {version}:")
                for cpe in cpes:
                    results.append(f"-- {cpe}")
            else:
                results.append(f"\n[+] No CPEs found for {software_name} version {version}.")
                cpes = []
        
            dlinks = dl_link_PS(f"{software_name} {version}")
            if dlinks:
                results.append(f"[!] Found {len(dlinks)} download links for {software_name} version {version}:")
                for dlink in dlinks:
                    results.append(f"-- {dlink}")
            else:
                results.append(f"[+] No download links found for {software_name} version {version}")
            marc_info = search_marc_info(f"{software_name}%20{version}")
            if marc_info:
                results.append("[!] Exploits found in Marc Full Disclosure")
                for result in marc_info:
                    if isinstance(result, dict) and 'Name' in result and 'Link' in result:
                        results.append(f"-- {result['Name']}: {result['Link']}")
                    else:
                        print(f"Invalid result format: {result}")
            else:
                results.append("[+] No exploits found in Marc Full Disclosure")
            cpe_num = len(cpes)
            if cpe_num > 0:
                #results.append("[!] Possible CVE Details")
                for cpe_string in cpes:
                    cve_details = fetch_cve_details(cpe_string)
                    if cve_details:
                        cve_details_list.extend(cve_details)
                        for detail in cve_details:
                            cve_id = detail["CVE ID"]
                            unique_cve_ids.add(cve_id)

                    # CVEDetails API call
                    cve_results = search_cves_by_cpe(cpe_string, bearer_token)
                    if cve_results:
                        #print(cve_results)
                        for cve in cve_results:
                            unique_cve_ids.add(cve['cveId'])
                # Unique CVEs found by CVEDetails
                results.append(f"[!] Found {len(unique_cve_ids)} unique CVEs.")
            else:
                results.append("[+] No CPE's to search for CVE's")
            for cpe_string in cpes:
                cve_details = fetch_cve_details(cpe_string)
                if cve_details:
                    cve_details_list.extend(cve_details)
                    for detail in cve_details:
                        cve_id = detail["CVE ID"]
                        unique_cve_ids.add(cve_id)

                # CVEDetails API call
                cve_results = search_cves_by_cpe(cpe_string, bearer_token)
                if cve_results:
                    #print(cve_results)
                    for cve in cve_results:
                        unique_cve_ids.add(cve['cveId'])

            # Process unique CVEs
            for cve_id in unique_cve_ids:
                detail = next((d for d in cve_details_list if d["CVE ID"] == cve_id), None)
                if detail:
                    results.append(f"--- {cve_id}: {detail.get('Description', 'N/A')}")
                    """
                    results.append(f"-- Short Name: {detail.get('Short Name', 'N/A')}")
                    results.append(f"-- Description: {detail.get('Description', 'N/A')}")
                    results.append(f"-- Weaknesses: {detail.get('Weaknesses', 'N/A')}")
                    results.append(f"-- Link: {detail.get('Link', 'N/A')}")
                    """

                cve_result = next((cr for cr in cve_results if cr['cveId'] == cve_id), None)
                if cve_result:
                    results.append(f"[-] {cve_id}: {cve_result.get('summary', 'N/A')}")
                    """
                    results.append(f"-- Summary: {cve_result.get('summary', 'N/A')}")
                    results.append(f"-- Publish Date: {cve_result.get('publishDate', 'N/A')}")
                    results.append(f"-- Update Date: {cve_result.get('updateDate', 'N/A')}")
                    results.append(f"-- Max CVSS Base Score: {cve_result.get('maxCvssBaseScore', 'N/A')}")
                    """
                    results.append(f"--- Exploit Exists: {cve_result.get('exploitExists', 'N/A')}")
                    
                    github_links = fetch_github_urls(cve_id)
                    if github_links:
                        results.append("--- Exploit/POC Over Github")
                        for link in github_links:
                            results.append(f"  {link}")
                        results.append("\n")
                    else:
                        results.append("--- Exploit/POC Over Github: None\n")
                    #results.append(f"-- Exploit Status: {detail.get('Exploit Status', 'N/A')}\n")
                else:
                    results.append(f"[-] {cve_id}: No CVE details found.")
        else:
            results.append(f"[-] Invalid entry in JSON file: {software}")

    if args.output:
        with open(args.output, 'w') as outfile:
            outfile.write("\n".join(results))
    else:
        print("\n".join(results))

if __name__ == "__main__":
    main()
