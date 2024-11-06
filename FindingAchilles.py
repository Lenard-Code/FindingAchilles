import requests
import json
import argparse
import re
import time
from bs4 import BeautifulSoup
from pyExploitDb import PyExploitDb

# Hardcoded API key
API_KEY = "6beeb12-b047-4fc9-a4a9-19d788cf059c"

def check_cves(software_name, version):
    url = f"https://nvd.nist.gov/products/cpe/search/results"
    params = {"namingFormat": "2.3", "keyword": f"{software_name} {version}"}
    headers = {
        "apiKey": API_KEY
    }
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        try:
            data = response.text
            cpe_pattern = re.compile(r'cpe:(.*?)<')
            cpes = cpe_pattern.findall(data)
            return cpes
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
            download_links = [f"https://packetstormsecurity.com{result['href']}" for result in results if '/files/download/' in result['href'] and result['href'].endswith('.txt')]
            if not download_links:
                print(f"No download links found for {product_name} (Packet Storm Security)")
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
                print(pre_tag)
                post_links = pre_tag.find_all('a', string=lambda text: "full-disc" not in text)
                results = [{"Name": link.get_text(strip=True), "Link": "https://marc.info" + link['href']} for link in post_links]
                if results:
                    return results
                else:
                    print("[+] No matching exploits found in Marc Full Disclosure.")
            else:
                print("[+] No matching exploits found in Marc Full Disclosure.")
        else:
            print(f"Failed to retrieve the web page. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error fetching Marc.Info data: {e}")
    return None

def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_cve_details = []
    for cpe_string in [cpe_string]:
        time.sleep(1)
        cve_query_string = ":".join(cpe_string.split(":")[1:5])
        url = f"{base_url}?cpeName=cpe:{cpe_string}"
        #print(f"Querying: {url}")

        try:
            headers = {
                "apiKey": API_KEY
            }
            response = requests.get(url, headers=headers)
            #response = requests.get(url)
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
        except requests.RequestException as e:
            continue
        except json.JSONDecodeError:
            print(f"Error decoding JSON for CPE: {cpe_string}. Skipping.")

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
                print(f"\n[!] Found {len(cpes)} CPEs for {software_name} version {version}:")
                #for cpe in cpes:
                #    print(f"{cpe}")
            else:
                print(f"\n[+] No CPEs found for {software_name} version {version}.")
            
            dlinks = dl_link_PS(f"{software_name} {version}")
            if dlinks:
                print(f"[!] Found {len(dlinks)} download links for {software_name} version {version}:")
                for dlink in dlinks:
                    print(f"-- {dlink}")

            marc_info = search_marc_info(f"{software_name}%20{version}")
            if marc_info:
                print("[!] Exploits found in Marc Full Disclosure")
                for result in marc_info:
                    print(f"-- {result['Name']}: {result['Link']}")
            else:
                continue
            for cpe_string in cpes:
                results = fetch_cve_details(cpe_string)
                if results:
                    #print("\nCVE Details")
                    for result in results:
                        cve_id = result["CVE ID"]
                        print(f"\nCVE ID: {cve_id}", "white")
                        if result["Short Name"]:
                            print(f"Short Name: {result['Short Name']}")
                        print(f"Description: {result['Description']}")
                        print(f"Weaknesses: {result['Weaknesses']}")
                        print(f"Link: {result['Link']}")

                        github_links = fetch_github_urls(cve_id)
                        if github_links:
                            print("\n[!] Exploit/POC Over Github")
                            for link in github_links:
                                print(f"  {link}")
                        else:
                            print("\nExploit/POC Over Github: None")
                        print(f"Exploit Status: {result['Exploit Status']}")
        else:
            print(f"[-] Invalid entry in JSON file: {software}")

if __name__ == "__main__":
    main()