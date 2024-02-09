import sys
import requests
import re
from termcolor import colored
import json
from pyExploitDb import PyExploitDb
from bs4 import BeautifulSoup
import subprocess

art = """
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
    params = {
        "namingFormat": "2.3",
        "keyword": f"{component} {version}"
    }

    response = requests.get(base_url, params=params)
    content = response.text

    cpe_matches = re.findall(r'cpe:(.*?)<', content)
    return cpe_matches

def synk_db(cve_id):
    res = requests.get(f"https://security.snyk.io/vuln/?search={cve_id}")
    a_tag_pattern = r'data-snyk-test="vuln table title".*>([^"]+)<!----><!---->'
    a_tag_matches = re.findall(a_tag_pattern, res.text)

    if a_tag_matches:
        snyk_short_name = a_tag_matches[0].strip()
        return snyk_short_name

def fetch_cve_details(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    cves = []

    for index, cpe_string in enumerate(cpe_strings[:2]):
        cve_query_string = ":".join(cpe_string.split(":")[1:5])
        url = f"{base_url}?cpeName=cpe:{cpe_string}"
        print(colored(f"Querying: {url}", "red"))

        response = requests.get(url)

        if response.status_code != 200:
            print(colored(f"Error: Unable to retrieve CVE data for CPE: {cpe_string}. Status code: {response.status_code}", "red"))
            return []

        try:
            data = response.json()
        except json.JSONDecodeError:
            print(colored(f"Error decoding JSON for CPE: {cpe_string}. Skipping.", "red"))
            return []

        for cve_item in data["vulnerabilities"]:

            all_cve_details = []

            cve_id = cve_item["cve"]["id"]
            description_text = cve_item["cve"]["descriptions"][0]["value"]
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            weaknesses = []
            for problem_type in cve_item["cve"]["weaknesses"]:
                for description in problem_type["description"]:
                    weaknesses.append(description["value"])

            pEdb = PyExploitDb()
            pEdb.debug = False
            pEdb.openFile()
            exploit_status = pEdb.searchCve(cve_id)
            if exploit_status:
                exploit_status = "Public Exploit Found over Exploit-DB"
            else:
                exploit_status = "No Public Exploit Found over Exploit-DB"
            
            snyk_short_name = synk_db(cve_id)

            all_cve_details.append({
                "CVE ID": cve_id,
                "Short Name": snyk_short_name,
                "Description": description_text,
                "Weaknesses": ", ".join(weaknesses),
                "Link": link,
                "Exploit Status": exploit_status
            })

    return all_cve_details

def fetch_github_urls(cve_id):
    api_url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
    response = requests.get(api_url)

    if response.status_code == 200:
        data = response.json()
        if "pocs" in data and data["pocs"]:
            github_urls = [poc["html_url"] for poc in data["pocs"]]
            return github_urls
    return []

def search_and_extract_download_links(product_name):
    search_url = f"https://packetstormsecurity.com/search/?q={product_name}"
    response = requests.get(search_url)

    download_links = []

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all('a', href=True)

        for result in results:
            href = result['href']
            if '/files/download/' in href and href.endswith('.txt'):
                download_links.append(f"https://packetstormsecurity.com{href}")

        if not download_links:
            print(colored("No download links found on Packet Storm Security.", "green", attrs=["underline"]))
            return None

    return download_links

def search_marc_info(search_term):
    # Make a GET request to the URL
    url = f"https://marc.info/?l=full-disclosure&s={search_term}"
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check if the response contains "No hits found for"
        if "No hits found for" in soup.get_text():
            print(colored("No matching exploits found.", "red", attrs=["underline"]))
        else:
            # Find all <a> tags within <pre> tags, excluding those with "full-disc" in the text
            post_links = soup.find('pre').find_all('a', string=lambda text: "full-disc" not in text)

            # Print all names and links
            if post_links:
                results = []
                for link in post_links:
                    name = link.get_text(strip=True)
                    link_url = "https://marc.info" + link['href']
                    results.append({"Name": name, "Link": link_url})
                return results
            else:
                print(colored("No matching exploits found.", "green"))
    else:
        print(colored("Failed to retrieve the web page.", "red"))
        print(f"Status code: {response.status_code}")
        return None

if __name__ == "__main__":
    print(colored("CVE and Exploit Finder Script", "green", attrs=["bold"]))
    print("This script searches for CVEs, exploits, and possible 0-Days for any product.\n")

    component = input(colored("Enter the component (e.g., Apache): ", "cyan"))
    version = input(colored("Enter the version (e.g., 4.2.1): ", "cyan"))

    cpe_strings = find_cpes(component, version)
    
    if cpe_strings:
        print(colored("CPEs Found:", "green"))
        for cpe_string in cpe_strings:
            print(colored(f"  {cpe_string}", "green"))
        
        for cpe_string in cpe_strings:
            results = fetch_cve_details(cpe_string)
            if results:
                print(colored("\nCVE Details", "cyan", attrs=["underline"]))
                for result in results:
                    cve_id = result["CVE ID"]
                    print(colored(f"\nCVE ID: {cve_id}", "white"))
                    if result["Short Name"]:
                        print(colored(f"Short Name: {result['Short Name']}", "light_blue"))
                    print(colored(f"Description: {result['Description']}", "yellow"))
                    if result["Weaknesses"]:
                        print(colored(f"Weaknesses: {result['Weaknesses']}", "magenta"))
                    print(colored(f"Link: {result['Link']}", "blue"))
                    github_urls = fetch_github_urls(cve_id)
                    if github_urls:
                        print(colored("Public Exploit/ POC Over Github found:", "red"))
                        for url in github_urls:
                            print(colored(f"  {url}", "blue"))
                    else:
                        print(colored("Public Exploit/ POC Over Github not found, you might need to check manually", "green"))
                    if result["Exploit Status"] == "Public Exploit Found":
                        print(colored(f"Exploit Status: {result['Exploit Status']}", "red"))
                    else:
                        print(colored(f"Exploit Status: {result['Exploit Status']}", "green"))
    else:
        print(colored("No CPEs found for the provided component and version.", "red"))
    
    # Search for download links on Packet Storm Security even if no CPEs were found
    download_links = search_and_extract_download_links(component)
    
    if download_links:
        print(colored("\nPossible Exploits on Packet Storm Security:", "cyan", attrs=["underline"]))
        for link in download_links:
            print(link)
    else:
        print(colored("No download links found on Packet Storm Security.", "red", attrs=["underline"]))

    # Search Marc.Info
    search_term_marc = f"{component} {version}"
    print(f"\nUsing keyword "+search_term_marc+" for lookup...")
    marc_results = search_marc_info(search_term_marc)
    if marc_results:
        print(colored("\nPossible Exploits:", "cyan", attrs=["underline"]))
        for result in marc_results:
            print(colored(f"\nName: {result['Name']}", "white"))
            print(colored(f"Link: {result['Link']}", "blue"))
