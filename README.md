# ThreatTracer - CVE Checker Script

![image](https://github.com/anmolksachan/ThreatTracer/assets/60771253/c557b992-00d9-408d-b1d4-7a9ce5e181c9)


This script fetches CVE details for a given component and version using relevant CPEs.

## Usage

1. Make sure you have Python installed on your system.
2. Install required libraries using `pip install requests colorama`.
3. Run the script using `python threattracer.py`.

## Script Description

This script uses the National Vulnerability Database (NVD) API to fetch Common Vulnerabilities and Exposures (CVE) details for a specified component and version.

## Features
1. CVE Finder Script: This script is designed to identify Common Vulnerabilities and Exposures (CVEs) based on the name and version of a component.
2. User-friendly Interaction: The script interacts with users to input the name and version of a software component, making it easy to search for CVEs.
3. Web Scraping: The script utilizes web scraping techniques to fetch Common Platform Enumeration (CPE) information from NIST's National Vulnerability Database (NVD).
4. Colorful Output: Output messages are color-coded using the termcolor library to enhance readability and provide a visually appealing experience.
5. CPE Search: The script searches for all matching CPEs for the specified component and version, displaying the URLs used for CPE retrieval.
6. CVE Querying: It then queries the NVD API using the CPE information to fetch CVE details for each CPE found.
7. Detailed Information: The script displays detailed information about each CVE, including the CVE ID, description, weaknesses, and link to the NVD page.
8. Robust Error Handling: The script handles cases where CPEs are not found, providing appropriate error messages to users.
9. Easy-to-Use: The user interface is designed to be straightforward, allowing users to quickly search for CVEs associated with a specific software version.
10. CPEs Enumeration: When multiple CPEs are found, the script lists all the discovered CPEs before proceeding to query CVE details for each one.
11. Reusability: The modular structure of the script makes it reusable and easy to integrate into other projects or scripts.
12. Interactive Prompt: The script employs an interactive prompt to guide users through the process of entering the software component and version.
13. Automated Querying: The script automates the process of querying and fetching CVE details, saving users time and effort.
14. API Integration: It leverages the NVD API to retrieve and present accurate CVE information for the specified software version.

### Prerequisites

- Python (3.6+ recommended)
- `requests` library (`pip install requests`)
- `termcolor` library (`pip install termcolor`)

### Execution

1. Run the script.
2. Enter the component (e.g., `jquery`).
3. Enter the version (e.g., `1.0.0`).

The script will display relevant CVE information, if available.

## Script Example
 ![image](https://github.com/anmolksachan/ThreatTracer/assets/60771253/a6d744f6-0473-45e4-a16a-399412ec8f12)

 ![image](https://github.com/anmolksachan/ThreatTracer/assets/60771253/128be6ce-7204-49b6-adaf-d7ec1f342a25)

## Sample Run
![Studio_Project_V2](https://github.com/anmolksachan/ThreatTracer/assets/60771253/a8938aa2-06cc-4fbf-a640-c10d77219185)

### Contact

Shoot my DM : [@FR13ND0x7F](https://twitter.com/fr13nd0x7f)

### Special Thanks
Contribute to be mentioned here.
[@FR13ND0x7F](https://twitter.com/fr13nd0x7f)
[@0xCaretaker](https://github.com/0xCaretaker)
[@meppohak5](https://github.com/meppohak5)

### Note
Feel free to enhance, modify, or contribute to this script to suit your needs and explore more security-related projects!

## __Want to support my work?__
Give me a Star in the repository or follow me [@FR13ND0x7F](https://twitter.com/fr13nd0x7f) , thats enough for me :P
