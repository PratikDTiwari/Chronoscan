# Chronoscan

**Chronoscan** is a powerful Python tool for discovering potential directory listings by leveraging archived URLs from the Wayback Machine. Designed for security researchers and penetration testers, Chronoscan automates the process of finding open directories and subdomains, facilitating efficient reconnaissance and security assessments.

---

## ✨ Features

- **Wayback Machine Integration:** Fetches archived URLs for any domain.
- **Directory Listing Detection:** Checks URLs for signs of open directory listings using customizable patterns.
- **Subdomain Discovery:** Automatically discovers and processes subdomains from Wayback data.
- **Concurrent Scanning:** Multi-threaded scanning for efficient processing of multiple targets.
- **Robust Error Handling:** Gracefully manages network issues, timeouts, and invalid input.
- **Detailed Logging:** Provides clear and informative output for easy analysis.
- **Customizable Patterns:** Easily adjust the patterns used to detect directory listings.

---

## 🚀 Quick Start

### Requirements

- **Python 3.7 or higher**
- **pip** (for installing dependencies)

### Installation

```bash
git clone https://github.com/yourusername/Chronoscan.git
cd Chronoscan
pip install requests```
---
### 🛠️ Usage
Command Line Options

usage: chronoscan.py [-h] (-d DOMAIN | -f FILE | -auto AUTO) [-t THREADS] [-v]

Chronoscan v1.0 - Enhanced Directory Listing Detection Using Wayback Machine

optional arguments:
  -h, --help            Show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Single target domain to scan (e.g., example.com)
  -f FILE, --file FILE  File containing a list of domains to scan (one per line)
  -auto AUTO            Automatically discover and scan subdomains for the given domain (e.g., example.com)
  -t THREADS, --threads THREADS
                        Number of threads for concurrent checks (default: 10)
  -v, --verbose         Enable verbose output (debug messages)

📝 Examples

Scan a single domain:

python chronoscan.py -d example.com

Scan multiple domains from a file:

python chronoscan.py -f domains.txt

Auto-discover and scan subdomains:

python chronoscan.py -auto example.com

Increase threads and enable verbose logging:

python chronoscan.py -d example.com -t 20 -v

🔧 Configuration

You can customize the tool by editing the CONFIG dictionary in the script.

Example Configuration:
CONFIG = {
    "USER_AGENT": "Chronoscan/1.0 (Enhanced; contact@example.com)",
    "DEFAULT_THREADS": 10,
    "TIMEOUT_SECONDS": 7,
    "DIRECTORY_LISTING_PATTERNS": [
        "Index of /",
        "Directory Listing for",
        "<title>Index of",
        "Parent Directory</a>",
        "Last modified</a>",
        "Name</a>",
        "Size</a>",
        "Description</a>",
        "<hr>",
        "Apache/2.4.6 (CentOS) Server at",
    ],
    "WAYBACK_CDX_URL": "https://web.archive.org/cdx/search/cdx",
}

📜 License
This project is licensed under the MIT License.
See the LICENSE file for details.

⚠️ Disclaimer
Chronoscan is intended for educational and authorized security testing only.
Always obtain permission before scanning any domain.
Unauthorized scanning may violate laws or terms of service.

🤝 Contributing
Contributions are welcome!
Feel free to open an issue or submit a pull request.

✉️ Contact
Author: FR13ND0x7F (@pratikdtiwari)
Email: Pratikdtiwari@gmail.com

**Happy hunting and stay secure!**

