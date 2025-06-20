# 📂 Chronoscan

**Chronoscan** is a robust Python tool designed for security researchers and penetration testers. It uncovers potential open directory listings by analyzing archived URLs from the Chronoscan Machine.

---

## ✨ Key Features

- **Chronoscan Machine Integration**
  - Retrieves archived URLs for any specified domain.
- **Directory Listing Detection**
  - Identifies open directory listings using customizable detection patterns.
- **Subdomain Discovery**
  - Automatically detects and scans subdomains from Chronoscan data.
- **Concurrent Scanning**
  - Utilizes multi-threading for efficient and fast processing.
- **Error Handling**
  - Handles network failures, timeouts, and invalid input gracefully.
- **Detailed Logging**
  - Outputs clear and informative logs for easy result analysis.
- **Configurable Patterns**
  - Easily modify directory listing detection patterns as needed.

---

## ⚙️ Requirements

- **Python**: Version 3.7 or above is required.
- **pip**: For installing dependencies.

---

## 🚀 Installation

```bash
git clone https://github.com/PratikDTiwari/Chronoscan.git
cd Chronoscan
pip install requests
```

---

## 🛠️ Usage

### Command-Line Options

```txt
usage: chronoscan.py [-h] (-d DOMAIN | -f FILE | -auto AUTO) [-t THREADS] [-v]
```

- `-h, --help`  
  Show the help message and exit.
- `-d DOMAIN, --domain DOMAIN`  
  Scan a single target domain (e.g., `example.com`).
- `-f FILE, --file FILE`  
  Scan multiple domains listed in a file (one domain per line).
- `-auto AUTO`  
  Automatically discover and scan subdomains for the given domain.
- `-t THREADS, --threads THREADS`  
  Number of concurrent threads (default: 10).
- `-v, --verbose`  
  Enable verbose output for detailed debug messages.

---

### 📝 Example Commands

- **Scan a single domain**
  ```bash
  python chronoscan.py -d example.com
  ```

- **Scan multiple domains from a file**
  ```bash
  python chronoscan.py -f domains.txt
  ```

- **Auto-discover and scan subdomains**
  ```bash
  python chronoscan.py -auto example.com
  ```

- **Increase threads and enable verbose logging**
  ```bash
  python chronoscan.py -d example.com -t 20 -v
  ```

---

## 🔧 Configuration

You can customize settings by editing the `CONFIG` dictionary in the script.

```python
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
    "Chronoscan_CDX_URL": "https://web.archive.org/cdx/search/cdx",
}
```

---

---

## 🐞 Troubleshooting

If you encounter errors such as timeouts or connection failures (e.g.):
```
ERROR - [-] Timeout error for <domain>: HTTPSConnectionPool(host='web.archive.org', port=443): Read timed out. (read timeout=7) [ReadTimeout]
ERROR - [-] Failed to fetch chronoscan URLs for <domain>. Cannot proceed.
```
**This means the request to the Wayback Machine took too long or your network connection was unstable.**

### How to Fix

- **Increase Timeout:**  
  Use the `--timeout` flag to allow more time for each request. Example:
  ```bash
  python chronoscan.py -d example.com --timeout 20
  ```
- **Check Internet Connection:**  
  Make sure your internet is working and stable.
- **Retry:**  
  Sometimes the Wayback Machine (web.archive.org) is slow or rate-limited. Wait a few minutes and try again.
- **Verbose Mode:**  
  Run with `-v` to see more detailed error messages for debugging.

---

## 📃 License

- **MIT License**
- See the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

- **Chronoscan is for educational and authorized security testing only.**
- Always obtain proper permission before scanning any domain.
- Unauthorized scanning may violate laws or terms of service.

---

## 🤝 Contributing

- Contributions are welcome!
- Open an issue or submit a pull request to improve the project.

---

## ✉️ Contact

- **Author:** 1n51d3H4ck3r1337 ([@pratikdtiwari](https://github.com/PratikDTiwari))
- **Email:** Pratikdtiwari@gmail.com

---

**Happy hunting and stay secure!**

---
