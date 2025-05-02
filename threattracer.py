import sys
import os
import requests
import re
import time
import json
from termcolor import colored
from bs4 import BeautifulSoup
from pyExploitDb import PyExploitDb
import argparse

# Configuration
CONFIG_FILE = os.path.expanduser("~/.cve_finder.cfg")

# ASCII Art Banner
art = r"""
  _______ _                    _ _______                      
 |__   __| |                  | |__   __|                     
    | |  | |__  _ __ ___  __ _| |_ | |_ __ __ _  ___ ___ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|| | '__/ _` |/__ / _ \ '__|
    | |  | | | | | |  __/ (_| | |_ | | | | (_| | (_|  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__||_|_|  \__,_|\___\___|_|  Version 3.0
 A Script to identify CVE and public exploits using CPE/CVE by name & version 
          -+ Hunt for 0Days and unpublished exploits +-
        Credit: @FR13ND0x7F @0xCaretaker @meppohak5
"""

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return f.read().strip()
    return None

def save_api_key(api_key):
    with open(CONFIG_FILE, 'w') as f:
        f.write(api_key)
    print(colored(f"API key stored in {CONFIG_FILE}", "green"))

def parse_args():
    parser = argparse.ArgumentParser(
        description="ThreatTracer: CVE and Exploit Finder Script\nNote: It is recommended to use NIST API Key: https://nvd.nist.gov/developers/request-an-api-key",
        epilog="Examples:\n"
               "  python3 threattracer.py -c 'PEEL SHOPPING' -v 9.4.0\n"
               "  python3 threattracer.py -c 'PEEL SHOPPING' -v 9.4.0 --more --poc\n"
               "  python3 threattracer.py --cpe 'cpe:2.3:a:peel:peel_shopping:9.4.0:*:*:*:*:*:*:*'\n"
               "  python3 threattracer.py --cve CVE-2021-44228",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--component", help="Component name (e.g., Apache) with version(-v/--version)")
    group.add_argument("--cpe", help="Direct CPE lookup (e.g., 'cpe:2.3:a:peel:peel_shopping:9.4.0:*:*:*:*:*:*:*')")
    group.add_argument("--cve", help="Direct CVE lookup (e.g., CVE-2021-27190)")
    parser.add_argument("-v", "--version", help="Component version (required with -c)")
    parser.add_argument("--api", help="NVD API key for authenticated requests")
    parser.add_argument("--apiStore", help="Store NVD API key for future use")
    parser.add_argument("--noapi", action="store_true", help="Force non-API mode")
    parser.add_argument("--poc", action="store_true", help="Show available PoCs (auto-enabled with --cpe/--cve)")
    parser.add_argument("--more", action="store_true", help="Show detailed descriptions (auto-enabled with --cpe/--cve)")
    
    args = parser.parse_args()
    
    # Auto-enable --poc and --more for CPE/CVE lookups
    if args.cpe or args.cve:
        args.poc = True
        args.more = True
    
    # Validate component-version combination
    if args.component and not args.version:
        parser.error("-c/--component requires -v/--version")
        
    # Validate CVE format
    if args.cve:
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        if not cve_pattern.match(args.cve.upper()):
            parser.error("Invalid CVE format. Expected format: CVE-YYYY-NNNNN")
            
    return args

args = parse_args()

# Handle API key storage
if args.apiStore:
    save_api_key(args.apiStore)
    sys.exit(0)

# Load API configuration
STORED_API_KEY = load_api_key()
USE_API = bool(args.api or STORED_API_KEY) and not args.noapi
API_KEY = args.api if args.api else STORED_API_KEY

print(colored(art, "cyan"))

def make_api_request(url, params=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    if USE_API and API_KEY:
        headers["apiKey"] = API_KEY

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get(url, params=params, headers=headers)
            
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 6))
                print(colored(f"⚠️ Rate limit exceeded. Retrying in {retry_after}s... ({attempt+1}/{max_retries})", "yellow"))
                time.sleep(retry_after)
                continue
                
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(colored(f"⚠️ Request failed: {e}. Retrying... ({attempt+1}/{max_retries})", "red"))
            time.sleep(2 ** attempt)
    
    print(colored("❌ Max retries exceeded. Fallback to non-API method", "red"))
    return None

def find_cpes(component, version):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    keyword = f"{component} {version}"
    params = {"keywordSearch": keyword}
    
    print(colored(f"\n🔍 Searching for: {keyword} using {'API' if USE_API else 'non-API'} method", "cyan"))
    
    data = make_api_request(url, params)
    if not data:
        return []
        
    return [item['cpe']['cpeName'] for item in data.get('products', [])]

def fetch_cve_details(cpe_string):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cpeName": cpe_string}
    
    data = make_api_request(url, params)
    if not data:
        return []
    
    vulnerabilities = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cve_id = cve.get('id', 'N/A')
        
        # Exploit check using PyExploitDb
        pEdb = PyExploitDb()
        pEdb.debug = False
        pEdb.openFile()
        exploit_status = "Public Exploit Found" if pEdb.searchCve(cve_id) else "No Public Exploit"
        
        # Trickest integration
        trickest_info = fetch_trickest_info(cve_id)
        
        vulnerabilities.append({
            "CVE ID": cve_id,
            "Description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
            "Weaknesses": ', '.join([desc['value'] for w in cve.get('weaknesses', []) for desc in w.get('description', [])]),
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "Exploit Status": exploit_status,
            "GitHub PoCs": trickest_info['github_pocs']
        })
        
    return vulnerabilities

def fetch_specific_cve(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    
    data = make_api_request(url, params)
    
    if not data or not data.get('vulnerabilities'):
        return None
        
    cve = data['vulnerabilities'][0].get('cve', {})
    
    # Exploit check using PyExploitDb
    pEdb = PyExploitDb()
    pEdb.debug = False
    pEdb.openFile()
    exploit_status = "Public Exploit Found" if pEdb.searchCve(cve_id) else "No Public Exploit"
    
    # Trickest integration
    trickest_info = fetch_trickest_info(cve_id)
    
    return [{
        "CVE ID": cve_id,
        "Description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
        "Weaknesses": ', '.join([desc['value'] for w in cve.get('weaknesses', []) for desc in w.get('description', [])]),
        "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "Exploit Status": exploit_status,
        "GitHub PoCs": trickest_info['github_pocs']
    }]

def fetch_trickest_info(cve_id):
    if not args.poc:
        return {"github_pocs": []}
    
    year = cve_id.split('-')[1]
    url = f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md"
    
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return {"github_pocs": []}
            
        github_pattern = re.compile(r'https://github\.com/[^\s)]+')
        return {
            "github_pocs": list(set(github_pattern.findall(response.text)))[:5]
        }
    except Exception as e:
        print(colored(f"⚠️ Error fetching Trickest data: {e}", "red"))
        return {"github_pocs": []}

def search_marc_info(search_term):
    url = f"https://marc.info/?l=full-disclosure&s={search_term}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if "No hits found for" in soup.get_text():
                return None
            post_links = soup.find('pre').find_all('a', string=lambda t: "full-disc" not in t)
            return [{"Name": link.text.strip(), "Link": "https://marc.info" + link['href']} for link in post_links]
    except Exception as e:
        print(colored(f"Error fetching Marc.Info data: {e}", "red"))
    return None

if __name__ == "__main__":
    print(colored("CVE and Exploit Finder Script", "green", attrs=["bold"]))
    
    # Handle direct CVE lookup
    if args.cve:
        cve_id = args.cve.upper()
        print(colored(f"\n🔍 Checking CVE: {cve_id}", "green"))
        
        # Validate CVE format again (in case of case issues)
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            print(colored("❌ Invalid CVE format. Expected format: CVE-YYYY-NNNNN", "red"))
            sys.exit(1)
        
        # Fetch CVE details
        cve_details = fetch_specific_cve(cve_id)
        if not cve_details:
            print(colored(f"❌ CVE {cve_id} not found in NVD database", "red"))
            sys.exit(1)
            
        # Marc Info check
        marc_info = search_marc_info(cve_id)
        if marc_info:
            print(colored("\nExploits found in Marc Full Disclosure", "yellow"))
            for result in marc_info:
                print(colored(f"{result['Name']}: {result['Link']}", "green"))
        else:
            print(colored("No Marc.Info exploits found", "red"))
            
        # Display CVE details
        print(colored("\nCVE Details", "cyan", attrs=["underline"]))
        for detail in cve_details:
            print(colored(f"\nCVE ID: {detail['CVE ID']}", "white"))
            print(colored(f"Description: {detail['Description']}", "yellow"))
            print(colored(f"Weaknesses: {detail['Weaknesses']}", "red"))
            print(colored(f"Link: {detail['Link']}", "blue"))
            print(colored(f"Exploit Status: {detail['Exploit Status']}", "red"))
            
            if detail['GitHub PoCs']:
                print(colored("\nGitHub PoCs (Trickest):", "yellow"))
                for link in detail['GitHub PoCs']:
                    print(colored(f"  {link}", "green"))
        sys.exit(0)
    
    # Handle direct CPE lookup
    if args.cpe:
        cpe_string = args.cpe
        print(colored(f"\n🔍 Checking CPE: {cpe_string}", "green"))
        cve_details = fetch_cve_details(cpe_string)
        
        if not cve_details:
            print(colored("  No CVEs found for this CPE", "red"))
            sys.exit(1)
            
        # Marc Info check (using CPE string)
        marc_info = search_marc_info(cpe_string)
        if marc_info:
            print(colored("\nExploits found in Marc Full Disclosure", "yellow"))
            for result in marc_info:
                print(colored(f"{result['Name']}: {result['Link']}", "green"))
        else:
            print(colored("No Marc.Info exploits found", "red"))
            
        # Display CVE details
        print(colored("\nCVE Details", "cyan", attrs=["underline"]))
        for detail in cve_details:
            print(colored(f"\nCVE ID: {detail['CVE ID']}", "white"))
            print(colored(f"Description: {detail['Description']}", "yellow"))
            print(colored(f"Weaknesses: {detail['Weaknesses']}", "red"))
            print(colored(f"Link: {detail['Link']}", "blue"))
            print(colored(f"Exploit Status: {detail['Exploit Status']}", "red"))
            
            if detail['GitHub PoCs']:
                print(colored("\nGitHub PoCs (Trickest):", "yellow"))
                for link in detail['GitHub PoCs']:
                    print(colored(f"  {link}", "green"))
        sys.exit(0)
    
    # Traditional component/version lookup
    component = args.component
    version = args.version
    
    # Find CPEs
    cpe_strings = find_cpes(component, version)
    if not cpe_strings:
        print(colored("No CPEs found. Please try different keywords.", "red"))
        sys.exit(0)
        
    print(colored("\nCPEs Found:", "green"))
    for cpe in cpe_strings:
        print(colored(f"  {cpe}", "green"))

    # Marc Full Disclosure Check
    marc_info = search_marc_info(f"{component} {version}")
    if marc_info:
        print(colored("\nExploits found in Marc Full Disclosure", "yellow"))
        for result in marc_info:
            print(colored(f"{result['Name']}: {result['Link']}", "green"))
    else:
        print(colored("No Marc.Info exploits found", "red"))

    # CVE Details Check
    for cpe in cpe_strings:
        print(colored(f"\n🔍 Checking CPE: {cpe}", "green"))
        cve_details = fetch_cve_details(cpe)
        
        if not cve_details:
            print(colored("  No CVEs found for this CPE", "red"))
            continue
            
        print(colored("\nCVE Details", "cyan", attrs=["underline"]))
        for detail in cve_details:
            print(colored(f"\nCVE ID: {detail['CVE ID']}", "white"))
            
            if args.more:
                print(colored(f"Description: {detail['Description']}", "yellow"))
                print(colored(f"Weaknesses: {detail['Weaknesses']}", "red"))
            
            print(colored(f"Link: {detail['Link']}", "blue"))
            print(colored(f"Exploit Status: {detail['Exploit Status']}", "red"))
            
            # GitHub PoC Check
            if args.poc and detail['GitHub PoCs']:
                print(colored("\nGitHub PoCs (Trickest):", "yellow"))
                for link in detail['GitHub PoCs']:
                    print(colored(f"  {link}", "green"))

    print(colored("\nHack The Planet!", "green", attrs=["underline"]))
