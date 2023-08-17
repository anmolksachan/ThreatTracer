import requests
import re
from termcolor import colored
from datetime import datetime

art = """
  _______ _                    _ _______                      
 |__   __| |                  | |__   __|                     
    | |  | |__  _ __ ___  __ _| |_ | |_ __ __ _  ___ ___ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|| | '__/ _` |/ __/ _ \ '__|
    | |  | | | | | |  __/ (_| | |_ | | | | (_| | (_|  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__||_|_|  \__,_|\___\___|_|  
    A Script to identify CVE using CPE by name & version 
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
    print(f"URL Used: {response.url}")  # Print the URL used to find CPE
    content = response.text

    cpe_matches = re.findall(r'cpe:(.*?)<', content)
    return cpe_matches

def synk_db(cve_id):
    res = requests.get(f"https://security.snyk.io/vuln/?search={cve_id}")
    a_tag_pattern = r'data-snyk-test="vuln table title".*>([^"]+)<!----><!---->'
    a_tag_matches = re.findall(a_tag_pattern, res.text)

    if a_tag_matches:
        snyk_short_name = a_tag_matches[0].lstrip().rstrip()
        return snyk_short_name

def fetch_cve_details(cpe_strings):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    results = []

    for cpe_string in cpe_strings:
        cve_query_string = ":".join(cpe_string.split(":")[1:5])  # Extract relevant CPE part (vendor, product, version, update)
        url = f"{base_url}?cpeMatchString=cpe:/{cve_query_string}"

        response = requests.get(url)
        data = response.json()

        if "result" in data:
            cves = data["result"]["CVE_Items"]
            for cve_item in cves:
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                snyk_short_name = synk_db(cve_id)

                description = cve_item["cve"]["description"]["description_data"][0]["value"]
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                weaknesses = []
                if "problemtype" in cve_item["cve"]:
                    for problem_type in cve_item["cve"]["problemtype"]["problemtype_data"]:
                        for description in problem_type["description"]:
                            weaknesses.append(description["value"])

                if "description_data" in cve_item["cve"]["description"]:
                    description_text = cve_item["cve"]["description"]["description_data"][0]["value"]
                else:
                    description_text = "Description not available."

                cve_details = {
                    "CVE ID": cve_id,
                    "Short Name": snyk_short_name,
                    "Description": description_text,
                    "Weaknesses": ", ".join(weaknesses),
                    "Link": link
                }

                results.append(cve_details)

    return results

if __name__ == "__main__":
    print(colored("CPE Finder Script", "green", attrs=["bold"]))
    print("This script searches for the CPEs of a component and version.\n")

    component = input(colored("Enter the component (e.g., jquery): ", "cyan"))
    version = input(colored("Enter the version (e.g., 1.0.0): ", "cyan"))

    cpe_strings = find_cpes(component, version)
    if cpe_strings:
        print(colored("CPEs Found:", "green"))
        for cpe_string in cpe_strings:
            print(colored(f"  {cpe_string}", "green"))
        
        export_option = input(colored("\nDo you want to export results to a text document? (yes/no): ", "yellow"))
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{component}_{version}_{timestamp}.txt"
        
        if export_option.lower() == "yes":
            results = fetch_cve_details(cpe_strings)
            with open(filename, "w") as f:
                for result in results:
                    f.write(f"CVE ID: {result['CVE ID']}\n")
                    if result["Short Name"]:
                        f.write(f"Short Name: {result['Short Name']}\n")
                    f.write(f"Description: {result['Description']}\n")
                    if result["Weaknesses"]:
                        f.write(f"Weaknesses: {result['Weaknesses']}\n")
                    f.write(f"Link: {result['Link']}\n\n")
            print(colored(f"Results exported to '{filename}'", "green"))
        
        results = fetch_cve_details(cpe_strings)
        for result in results:
            print(colored("\nCVE Details", "cyan", attrs=["underline"]))
            print(colored(f"CVE ID: {result['CVE ID']}", "red"))
            if result["Short Name"]:
                print(colored(f"Short Name: {result['Short Name']}", "green"))
            print(colored(f"Description: {result['Description']}", "yellow"))
            if result["Weaknesses"]:
                print(colored(f"Weaknesses: {result['Weaknesses']}", "magenta"))
            print(colored(f"Link: {result['Link']}\n", "blue"))
    else:
        print(colored("CPEs not found for the provided component and version.", "red"))
