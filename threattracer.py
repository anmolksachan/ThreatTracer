import sys
import os
import requests
import re
import time
import json
import csv
from io import StringIO
from termcolor import colored
from bs4 import BeautifulSoup
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
        description="ThreatTracer: CVE and Exploit Finder Script",
        epilog="Examples:\n"
               "  python3 threattracer.py -c 'PEEL SHOPPING' -v 9.4.0\n"
               "  python3 threattracer.py --cpe 'cpe:2.3:a:peel:peel_shopping:9.4.0:*:*:*:*:*:*:*'\n"
               "  python3 threattracer.py --cve CVE-2021-44228",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--component", help="Component name (e.g., Apache) with version(-v/--version)")
    group.add_argument("--cpe", help="Direct CPE lookup")
    group.add_argument("--cve", help="Direct CVE lookup")
    parser.add_argument("-v", "--version", help="Component version (required with -c)")
    parser.add_argument("--api", help="NVD API key for authenticated requests")
    parser.add_argument("--apiStore", help="Store NVD API key for future use")
    parser.add_argument("--noapi", action="store_true", help="Force non-API mode")
    parser.add_argument("--poc", action="store_true", help="Show available PoCs")
    parser.add_argument("--more", action="store_true", help="Show detailed descriptions")

    args = parser.parse_args()

    if args.cpe or args.cve:
        args.poc = True
        args.more = True

    if args.component and not args.version:
        parser.error("-c/--component requires -v/--version")

    if args.cve:
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        if not cve_pattern.match(args.cve.upper()):
            parser.error("Invalid CVE format. Expected format: CVE-YYYY-NNNNN")

    return args

args = parse_args()

if args.apiStore:
    save_api_key(args.apiStore)
    sys.exit(0)

STORED_API_KEY = load_api_key()
USE_API = bool(args.api or STORED_API_KEY) and not args.noapi
API_KEY = args.api if args.api else STORED_API_KEY

print(colored(art, "cyan"))

# Cache for Exploit-DB CSV
exploit_db_cache = None

def get_exploit_db():
    global exploit_db_cache
    if exploit_db_cache is not None:
        return exploit_db_cache
    
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"
    try:
        response = requests.get(url)
        response.raise_for_status()
        csv_content = StringIO(response.text)
        reader = csv.DictReader(csv_content)
        exploit_db_cache = {row['id']: row for row in reader}
        return exploit_db_cache
    except Exception as e:
        print(colored(f"⚠️ Failed to fetch Exploit-DB: {e}", "red"))
        return {}

def search_exploitdb(cve_id):
    exploits = []
    cve_id = cve_id.lower()
    exploit_db = get_exploit_db()
    
    for exp_id, data in exploit_db.items():
        if cve_id in data.get('codes', '').lower():
            exploits.append({
                'id': exp_id,
                'description': data['description'],
                'link': f"https://www.exploit-db.com/exploits/{exp_id}"
            })
    return exploits

def make_api_request(url, params=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    if USE_API and API_KEY:
        headers["apiKey"] = API_KEY
    for attempt in range(3):
        try:
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 6))
                print(colored(f"⚠️ Rate limit exceeded. Retrying in {retry_after}s...", "yellow"))
                time.sleep(retry_after)
                continue
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(colored(f"⚠️ Request failed: {e}", "red"))
            time.sleep(2 ** attempt)
    return None

def find_cpes(component, version):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    keyword = f"{component} {version}"
    print(colored(f"\n🔍 Searching for: {keyword}", "cyan"))
    data = make_api_request(url, {"keywordSearch": keyword})
    if not data:
        return []
    return [item['cpe']['cpeName'] for item in data.get('products', [])]

def fetch_trickest_info(cve_id):
    if not args.poc:
        return []
    year = cve_id.split('-')[1]
    url = f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return []
        return list(set(re.findall(r'https://github\.com/[^\s)]+', response.text)))[:5]
    except:
        return []

def fetch_cve_details_by_cve(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    data = make_api_request(url, {"cveId": cve_id})
    if not data:
        return []
    vulnerabilities = []
    for item in data.get('vulnerabilities', []):
        cve = item['cve']
        cve_id = cve['id']
        exploits = search_exploitdb(cve_id)
        trickest_links = fetch_trickest_info(cve_id)
        vulnerabilities.append({
            "CVE ID": cve_id,
            "Description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
            "Weaknesses": ', '.join([d['value'] for w in cve.get('weaknesses', []) for d in w.get('description', [])]),
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "Exploits": exploits,
            "GitHub PoCs": trickest_links
        })
    return vulnerabilities

def fetch_cve_details_by_cpe(cpe_string):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    data = make_api_request(url, {"cpeName": cpe_string})
    if not data:
        return []
    vulnerabilities = []
    for item in data.get('vulnerabilities', []):
        cve = item['cve']
        cve_id = cve['id']
        exploits = search_exploitdb(cve_id)
        trickest_links = fetch_trickest_info(cve_id)
        vulnerabilities.append({
            "CVE ID": cve_id,
            "Description": cve.get('descriptions', [{}])[0].get('value', 'N/A'),
            "Weaknesses": ', '.join([d['value'] for w in cve.get('weaknesses', []) for d in w.get('description', [])]),
            "Link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "Exploits": exploits,
            "GitHub PoCs": trickest_links
        })
    return vulnerabilities

def print_cve_info(details):
    for d in details:
        print(colored(f"\nCVE ID: {d['CVE ID']}", "white"))
        print(colored(f"Description: {d['Description']}", "yellow"))
        print(colored(f"Weaknesses: {d['Weaknesses']}", "red"))
        print(colored(f"Link: {d['Link']}", "blue"))
        
        if d['Exploits']:
            print(colored("\nExploit-DB Entries:", "magenta"))
            for exp in d['Exploits']:
                print(f"  ID: {exp['id']}")
                print(f"  Description: {exp['description']}")
                print(f"  Link: {exp['link']}")
        
        if d['GitHub PoCs']:
            print(colored("\nGitHub PoCs:", "cyan"))
            for link in d['GitHub PoCs']:
                print(f"  {link}")

def main():
    if args.cve:
        print(colored(f"\n🔍 Checking CVE: {args.cve.upper()}", "green"))
        details = fetch_cve_details_by_cve(args.cve.upper())
        print_cve_info(details)
        return

    if args.cpe:
        print(colored(f"\n🔍 Checking CPE: {args.cpe}", "green"))
        details = fetch_cve_details_by_cpe(args.cpe)
        print_cve_info(details)
        return

    cpes = find_cpes(args.component, args.version)
    if not cpes:
        print(colored("❌ No CPEs found.", "red"))
        return

    print(colored("\nCPEs Found:", "green"))
    for c in cpes:
        print(f" - {c}")

    for c in cpes:
        print(colored(f"\n🔍 Checking CVEs for: {c}", "green"))
        details = fetch_cve_details_by_cpe(c)
        print_cve_info(details)

if __name__ == "__main__":
    main()
