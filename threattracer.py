import sys
import requests
import re
from termcolor import colored
import json
from pyExploitDb import PyExploitDb
from bs4 import BeautifulSoup

art = r"""
  _______ _                    _ _______                      
 |__   __| |                  | |__   __|                     
    | |  | |__  _ __ ___  __ _| |_ | |_ __ __ _  ___ ___ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|| | '__/ _` |/__ / _ \ '__|
    | |  | | | | | |  __/ (_| | |_ | | | | (_| | (_|  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__||_|_|  \__,_|\___\___|_|  Version 2.2
 A Script to identify CVE and public exploits using CPE by name & version 
          -+ Hunt for 0Days and unpublished exploits +-
        Credit: @FR13ND0x7F @0xCaretaker @meppohak5
"""

print(colored(art, "cyan"))

def find_cpes(component, version):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {"namingFormat": "2.3", "keyword": f"{component} {version}"}

    try:
        response = requests.get(base_url, params=params, verify=True)
        response.raise_for_status()
        content = response.text
        cpe_matches = re.findall(r'cpe:(.*?)<', content)
        return cpe_matches
    except requests.RequestException as e:
        print(colored(f"Error fetching CPEs: {e}", "red"))
        return []

def synk_db(cve_id):
    try:
        res = requests.get(f"https://security.snyk.io/vuln/?search={cve_id}")
        a_tag_pattern = r'data-snyk-test="vuln table title".*>([^"]+)<!----><!---->'
        a_tag_matches = re.findall(a_tag_pattern, res.text)
        if a_tag_matches:
            return a_tag_matches[0].strip()
    except requests.RequestException as e:
        print(colored(f"Error fetching Snyk data: {e}", "red"))
    return None

def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_cve_details = []

    for cpe_string in [cpe_string]:
        cve_query_string = ":".join(cpe_string.split(":")[1:5])
        url = f"{base_url}?cpeName=cpe:{cpe_string}"
        print(colored(f"Querying: {url}", "red"))

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
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
            print(colored(f"Request error: {e}", "red"))
        except json.JSONDecodeError:
            print(colored(f"Error decoding JSON for CPE: {cpe_string}. Skipping.", "red"))

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
        print(colored(f"Error fetching GitHub URLs: {e}", "red"))
    return []

def search_and_extract_download_links(product_name):
    search_url = f"https://packetstormsecurity.com/search/?q={product_name}"
    try:
        response = requests.get(search_url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', href=True)
            download_links = [f"https://packetstormsecurity.com{result['href']}" for result in results if '/files/download/' in result['href'] and result['href'].endswith('.txt')]
            if not download_links:
                print(colored("No download links found on Packet Storm Security.", "green", attrs=["underline"]))
            return download_links
    except requests.RequestException as e:
        print(colored(f"Error fetching download links: {e}", "red"))
    return []

def search_marc_info(search_term):
    url = f"https://marc.info/?l=full-disclosure&s={search_term}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if "No hits found for" in soup.get_text():
                print(colored("No matching exploits found.", "red", attrs=["underline"]))
            else:
                post_links = soup.find('pre').find_all('a', string=lambda text: "full-disc" not in text)
                results = [{"Name": link.get_text(strip=True), "Link": "https://marc.info" + link['href']} for link in post_links]
                if results:
                    return results
                else:
                    print(colored("No matching exploits found.", "green"))
        else:
            print(colored(f"Failed to retrieve the web page. Status code: {response.status_code}", "red"))
    except requests.RequestException as e:
        print(colored(f"Error fetching Marc.Info data: {e}", "red"))
    return None

if __name__ == "__main__":
    print(colored("CVE and Exploit Finder Script", "green", attrs=["bold"]))
    print("This script searches for CVEs, exploits, and possible 0-Days for any product.\n")

    component = input(colored("Enter the component (e.g., Apache): ", "cyan"))
    version = input(colored("Enter the version (e.g., 4.2.1): ", "cyan"))

    # Fetch and display CPEs
    cpe_strings = find_cpes(component, version)
    if cpe_strings:
        print(colored("CPEs Found:", "green"))
        for cpe_string in cpe_strings:
            print(colored(f"  {cpe_string}", "green"))
    else:
        print(colored("No CPEs found. Please try different keywords.", "red"))
        sys.exit(0)

    # Search for Packet Storm Security download links
    download_links = search_and_extract_download_links(f"{component} {version}")
    if download_links:
        print(colored("\nPublic exploits found over Packet Storm Security", "yellow"))
        for link in download_links:
            print(colored(f"  {link}", "blue"))

    # Search Marc Full Disclosure for exploits
    marc_info = search_marc_info(f"{component} {version}")
    if marc_info:
        print(colored("\nExploits found in Marc Full Disclosure", "yellow"))
        for result in marc_info:
            print(colored(f"{result['Name']}: {result['Link']}", "green"))
    else:
        print(colored("\nNo exploits found in Marc Full Disclosure.", "red"))

    # Process each CPE string to get CVE details
    for cpe_string in cpe_strings:
        results = fetch_cve_details(cpe_string)
        if results:
            print(colored("\nCVE Details", "cyan", attrs=["underline"]))
            for result in results:
                cve_id = result["CVE ID"]
                print(colored(f"\nCVE ID: {cve_id}", "white"))
                if result["Short Name"]:
                    print(colored(f"Short Name: {result['Short Name']}", "magenta"))
                print(colored(f"Description: {result['Description']}", "yellow"))
                print(colored(f"Weaknesses: {result['Weaknesses']}", "red"))
                print(colored(f"Link: {result['Link']}", "blue"))

                github_links = fetch_github_urls(cve_id)
                if github_links:
                    print(colored("\nExploit/POC Over Github", "yellow"))
                    for link in github_links:
                        print(colored(f"  {link}", "green"))
                else:
                    print(colored("\nExploit/POC Over Github: None", "green"))
                print(colored(f"Exploit Status: {result['Exploit Status']}", "red"))

    print(colored("Hack The Planet!", "green", attrs=["underline"]))
