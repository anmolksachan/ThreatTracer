# ThreatTracer - CVE Checker, [Public Exploit Enumerater](https://github.com/anmolksachan/ThreatTracer/blob/main/README.md#public-exploit) and [ZeroDay](https://github.com/anmolksachan/ThreatTracer/assets/60771253/65328a63-a0dd-4902-b7f9-0346564480dc) finder against any product and much more

<!--![ThreatTracer Banner version 2 1 OLD ](https://github.com/anmolksachan/ThreatTracer/assets/60771253/77092c9f-f3f2-401d-8b16-d4a21a945249)-->
<!--![ThreatTracer Banner version 2 1 ](https://github.com/anmolksachan/ThreatTracer/assets/60771253/58f8e429-700d-4067-a007-518ee00a7ef7)-->
<!--<img alt="Screenshot 2024-02-09 at 7 05 14 PM" src="https://github.com/anmolksachan/ThreatTracer/assets/60771253/1be90c9e-ac0a-4038-b0f5-7aa4e5cde29f">-->
![image](https://github.com/user-attachments/assets/b5745616-d052-4c79-b0b3-774377f41ab0)

> Find CVEs, public exploits, and 0-Day vulnerabilities for any software component.

## Key Features ✨
- 🔍 **Multi-mode Search**: Lookup by:
  - Component & Version (`-c apache -v 2.4`)
  - Direct CPE (`--cpe cpe:2.3:a:apache:http_server:2.4`)
  - Specific CVE (`--cve CVE-2021-44228`)
- 🚀 **NVD API Integration** with API key support for faster queries
- 📦 **Trickest PoC Database** integration for GitHub exploit lookup
- 📬 **Marc Full Disclosure** exploit search integration
- 🛡️ **Exploit-DB** lookup is removed with static code for faster results.
- ⚡ **Rate limiting** with automatic retry system
- 🔐 **API Key Management** with persistent storage
- 📊 **Detailed Output** with color-coded results

## Installation 🛠️
```bash
git clone https://github.com/anmolksachan/ThreatTracer.git
```
```bash
cd ThreatTracer
```
```bash
pip3 install -r requirements.txt
```
```bash
python3 threattracer.py -h
```

## Configure ⚙️
```bash 
$ sudo python3 threattracer.py --apiStore <API KEY> -c 'Peel Shopping' -v '9.3.0'
API key stored in /root/.cve_finder.cfg
```
Request API Key here: https://nvd.nist.gov/developers/request-an-api-key

## Usage 🚀
```bash
python3 threattracer.py --help
```
# Basic usage

```bash
python3 threattracer.py -c "Apache" -v "2.4.56"
```
# Advanced options
```bash
python3 threattracer.py -c 'Peel Shopping' -v '9.3.0' --poc --more
```
```bash
python3 threattracer.py --cpe "cpe:2.3:a:peel:peel_shopping:9.4.0"
```
```bash
python3 threattracer.py --cve CVE-2021-27190
```

## Examples 📌 

 Component search with PoC lookup
```bash
python3 threattracer.py -c 'PEEL SHOPPING' -v "9.4.0" --poc
```
 Direct CVE analysis
```bash
python3 threattracer.py --cve CVE-2021-27190
```
 Store API key for repeated use
```bash
python3 threattracer.py --apiStore YOUR_API_KEY_HERE
```

## Sample Run 📟/ Output Preview 🖥️
- Help
![image](https://github.com/user-attachments/assets/ab47f588-9388-4268-b531-73e92a0a4fc1)

- Configure NIST API Key to avoid getting rate limited [Recommended]
![image](https://github.com/user-attachments/assets/714ddb75-b6d3-4f40-b18f-9106946e489b)

- Lookup for component and version
![image](https://github.com/user-attachments/assets/69b3d89e-26db-4a2b-8a68-e319341200f0)

- Lookup for component and version with --more to get detailed description of each CVE and --poc to lookup for POCs/ Exploits.
![image](https://github.com/user-attachments/assets/e767f004-d5a4-495d-b68c-ca27c62d1ebe)

- Direct CVE lookup
![image](https://github.com/user-attachments/assets/d0276a2e-e7d0-4b99-9f7a-b8456c5729c6)

- Direct CPE lookup
![image](https://github.com/user-attachments/assets/c6504bd5-d574-4b54-a4e4-d839cecff75d)

- Not interested in configuring API, directly use from the threattracer
![image](https://github.com/user-attachments/assets/20cedf8a-3592-4c38-a10a-7df5b154bbfd)

- Force threattracer to not use NIST API even if its configured in environment
![image](https://github.com/user-attachments/assets/e05eea1a-8eb0-46eb-b56a-19692b6e657c)

- Updated exploitDB module with detailed output and faster execution
![image](https://github.com/user-attachments/assets/ed09433d-b850-4e8b-9fcb-b297087aebaf)

## Features Breakdown 💡 

   1. CVE Detection  via NVD API
   2. Exploit Verification  through:
        - Static mode via ExploitDB
        - GitHub PoC database
        - Marc Full Disclosure
         
   3. Zero-Day Hunting  capabilities
   4. Rate Limit Handling  with automatic retries
   5. Persistent API Key  storage

## Requirements 📋 
```bash
pip3 install -r requirements.txt
```
## Contributors 🤝
Mayur Patil [@meppohak5](https://github.com/meppohak5) <br>
Deepak Dhasmana [@0xCaretaker](https://github.com/0xCaretaker) <br>
Contribute to be mentioned here.

## Read More:
Version 1: [Enhancing Penetration Testing with CVE Checker Script — ThreatTracer](https://anmolksachan.medium.com/enhancing-penetration-testing-with-cve-checker-script-threattracer-p-484487747a77)<br>
Version 3: [ThreatTracer 3.0: Redefining Vulnerability Intelligence for Modern Defenders](https://anmolksachan.medium.com/threattracer-3-0-redefining-vulnerability-intelligence-for-modern-defenders-7661ffc11873)

## Note
Feel free to enhance, modify, or contribute to this script to suit your needs and explore more security-related projects!

## Support ❤️ 

   ⭐ Star this repository<br>
   📣 Follow  [@FR13ND0x7F](https://twitter.com/fr13nd0x7f)<br>
   🤝 Contribute through pull requests

## Disclaimer ⚠️ 

This tool is for educational and ethical security testing purposes only. Use only on systems you own or have explicit permission to test. 

## License 📜 

[MIT License](https://github.com/anmolksachan/ThreatTracer?tab=MIT-1-ov-file#readme)  - Copyright (c) 2024 Anmol Sachan 
