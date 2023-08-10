# ThreatTracer - CVE Checker Script

![CVE Checker Art](link_to_your_image_here) <!-- Replace with a link to your ASCII art image -->

This script fetches CVE details for a given component and version.

## Usage

1. Make sure you have Python installed on your system.
2. Install required libraries using `pip install requests colorama`.
3. Run the script using `python threattracer.py`.

## Script Description

This script uses the National Vulnerability Database (NVD) API to fetch Common Vulnerabilities and Exposures (CVE) details for a specified component and version.

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

```python
import requests
from termcolor import colored

# ... (your script code here)

