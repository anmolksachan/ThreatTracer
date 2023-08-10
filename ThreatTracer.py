import requests
from termcolor import colored

art = """
  _______ _                    _ _______                      
 |__   __| |                  | |__   __|                     
    | |  | |__  _ __ ___  __ _| |_ | |_ __ __ _  ___ ___ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|| | '__/ _` |/ __/ _ \ '__|
    | |  | | | | | |  __/ (_| | |_ | | | | (_| | (_|  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__||_|_|  \__,_|\___\___|_|  
  A Script to identify CVE by name & version by @FR13ND0x7F
"""

print(art)                                                              


def fetch_cve_details(component, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    query = f"cpe:/a:jquery:jquery:{version}"
    url = f"{base_url}?cpeMatchString={query}"
    
    response = requests.get(url)
    data = response.json()

    if "result" in data:
        cves = data["result"]["CVE_Items"]
        print(colored("\nCVE Details\n", "cyan", attrs=["underline"]))
        for cve_item in cves:
            cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
            description = cve_item["cve"]["description"]["description_data"][0]["value"]
            
            print(colored(f"CVE ID: {cve_id}", "red"))
            print(colored(f"Description: {description}\n", "yellow"))

if __name__ == "__main__":
    print(colored("CVE Checker Script", "green", attrs=["bold"]))
    print(colored("This script fetches CVE details for a given component and version.\n", "white"))

    component = input(colored("Enter the component (e.g., jquery): ", "cyan"))
    version = input(colored("Enter the version (e.g., 1.0.0): ", "cyan"))

    fetch_cve_details(component, version)
