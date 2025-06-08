import requests
import re
import os
import tempfile
import logging
import sys
import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Set

# --- Configuration ---
CONFIG = {
    "USER_AGENT": "ArchivEye/1.0 (Enhanced; contact@example.com)",
    "DEFAULT_THREADS": 10,
    "TIMEOUT_SECONDS": 7,  # Increased timeout slightly for network fluctuations
    "DIRECTORY_LISTING_PATTERNS": [
        "Index of /",
        "Directory Listing for",
        "<title>Index of",
        "Parent Directory</a>",
        "Last modified</a>",
        "Name</a>",
        "Size</a>",
        "Description</a>",
        "<hr>",  # Common in Apache directory listings
        "Apache/2.4.6 (CentOS) Server at",  # Specific server versions
    ],
    "chronoscan_CDX_URL": "https://web.archive.org/cdx/search/cdx",
}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def display_banner() -> None:
    """Displays the tool's ASCII art banner."""
    banner = r"""

 ▄████▄  ██░ ██ ██▀███  ▒█████  ███▄    █ ▒█████   ██████ ▄████▄  ▄▄▄      ███▄    █ 
▒██▀ ▀█ ▓██░ ██▓██ ▒ ██▒██▒  ██▒██ ▀█   █▒██▒  ██▒██    ▒▒██▀ ▀█ ▒████▄    ██ ▀█   █ 
▒▓█    ▄▒██▀▀██▓██ ░▄█ ▒██░  ██▓██  ▀█ ██▒██░  ██░ ▓██▄  ▒▓█    ▄▒██  ▀█▄ ▓██  ▀█ ██▒
▒▓▓▄ ▄██░▓█ ░██▒██▀▀█▄ ▒██   ██▓██▒  ▐▌██▒██   ██░ ▒   ██▒▓▓▄ ▄██░██▄▄▄▄██▓██▒  ▐▌██▒
▒ ▓███▀ ░▓█▒░██░██▓ ▒██░ ████▓▒▒██░   ▓██░ ████▓▒▒██████▒▒ ▓███▀ ░▓█   ▓██▒██░   ▓██░
░ ░▒ ▒  ░▒ ░░▒░░ ▒▓ ░▒▓░ ▒░▒░▒░░ ▒░   ▒ ▒░ ▒░▒░▒░▒ ▒▓▒ ▒ ░ ░▒ ▒  ░▒▒   ▓▒█░ ▒░   ▒ ▒ 
  ░  ▒   ▒ ░▒░ ░ ░▒ ░ ▒░ ░ ▒ ▒░░ ░░   ░ ▒░ ░ ▒ ▒░░ ░▒  ░ ░ ░  ▒    ▒   ▒▒ ░ ░░   ░ ▒░
░        ░  ░░ ░ ░░   ░░ ░ ░ ▒    ░   ░ ░░ ░ ░ ▒ ░  ░  ░ ░         ░   ▒     ░   ░ ░ 
░ ░      ░  ░  ░  ░        ░ ░          ░    ░ ░       ░ ░ ░           ░  ░        ░ 
░                                                        ░                           

                  Chronoscan v1.0 by 1n51d3H4ck3r1337 (Enhanced)
        Discover potential directory listings through archived URLs from the chronoscan Machine.
    """
    logger.info(banner)
    logger.info("  Crafted by 1n51d3H4ck3r1337 @anmolksachan — for the community, by the community.")
    logger.info("  This tool is meant for educational and authorized security testing only.")
    logger.info("-" * 80)

def fetch_chronoscan_urls(domain: str) -> Optional[str]:
    """
    Fetches archived URLs for a given domain from the chronoscan Machine CDX API.

    Args:
        domain: The target domain (e.g., "example.com").

    Returns:
        The path to a temporary file containing the fetched URLs, or None if an error occurs.
    """
    logger.info(f"[+] Querying chronoscan Machine for {domain}...")
    params = {
        "url": f"*.{domain}/*",
        "output": "txt",
        "fl": "original",
        "collapse": "urlkey",
        "page": "/",
        "limit": 100000  # Increased limit for more comprehensive results
    }
    headers = {'User-Agent': CONFIG["USER_AGENT"]}
    temp_file_path = None
    try:
        with requests.get(
            CONFIG["chronoscan_CDX_URL"],
            params=params,
            stream=True,
            headers=headers,
            timeout=CONFIG["TIMEOUT_SECONDS"]
        ) as response:
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False, mode="w+", encoding="utf-8") as temp_file:
                temp_file_path = temp_file.name
                for line in response.iter_lines(decode_unicode=True):
                    if line.strip():
                        temp_file.write(line.strip() + "\n")
                logger.debug(f"Successfully fetched chronoscan URLs to temporary file: {temp_file_path}")
            return temp_file_path
    except requests.exceptions.HTTPError as e:
        logger.error(f"[-] HTTP error fetching chronoscan data for {domain}: {e} (Status Code: {e.response.status_code})")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"[-] Connection error fetching chronoscan data for {domain}: {e}")
    except requests.exceptions.Timeout as e:
        logger.error(f"[-] Timeout fetching chronoscan data for {domain}: {e}")
    except requests.exceptions.RequestException as e:
        logger.error(f"[-] An unexpected request error occurred for {domain}: {e}")
    except Exception as e:
        logger.error(f"[-] An unexpected error occurred during chronoscan data fetching for {domain}: {e}")
    return None

def extract_paths_for_domain(temp_file_path: str, target_domain: str) -> List[str]:
    """
    Extracts unique paths relevant to the target domain from a file of URLs.

    Args:
        temp_file_path: Path to the temporary file containing chronoscan URLs.
        target_domain: The domain for which to extract paths.

    Returns:
        A sorted list of unique URL paths.
    """
    unique_paths: Set[str] = set()
    try:
        with open(temp_file_path, "r", encoding="utf-8", errors='ignore') as temp_file:
            for line in temp_file:
                url = line.strip()
                if not url:
                    continue
                try:
                    parsed_url = urlparse(url)
                    if parsed_url.hostname and (
                        parsed_url.hostname == target_domain
                        or parsed_url.hostname.endswith(f".{target_domain}")
                    ):
                        path = parsed_url.path
                        if path and path != "/":
                            if "." not in os.path.basename(path) and not path.endswith('/'):
                                path += '/'
                            unique_paths.add(path)
                except ValueError as e:
                    logger.debug(f"Skipping malformed URL '{url}': {e}")
    except FileNotFoundError:
        logger.error(f"[-] Temporary file not found: {temp_file_path}")
    except Exception as e:
        logger.error(f"[-] Error extracting paths from {temp_file_path}: {e}")
    return sorted(unique_paths)

def extract_subdomains(temp_file_path: str, base_domain: str) -> List[str]:
    """
    Extracts unique subdomains from a file of URLs belonging to a base domain.

    Args:
        temp_file_path: Path to the temporary file containing chronoscan URLs.
        base_domain: The base domain (e.g., "example.com").

    Returns:
        A sorted list of unique subdomains.
    """
    subdomains: Set[str] = set()
    domain_pattern = re.compile(rf"^(?:[a-zA-Z0-9-]+\.)*{re.escape(base_domain)}$", re.IGNORECASE)
    try:
        with open(temp_file_path, "r", encoding="utf-8", errors='ignore') as temp_file:
            for line in temp_file:
                url = line.strip()
                if not url:
                    continue
                try:
                    parsed_url = urlparse(url)
                    hostname = parsed_url.hostname
                    if hostname and hostname != base_domain and domain_pattern.match(hostname):
                        subdomains.add(hostname)
                except ValueError as e:
                    logger.debug(f"Skipping malformed URL '{url}' during subdomain extraction: {e}")
    except FileNotFoundError:
        logger.error(f"[-] Temporary file not found: {temp_file_path}")
    except Exception as e:
        logger.error(f"[-] Error extracting subdomains from {temp_file_path}: {e}")
    return sorted(subdomains)

def check_directory_listing(domain: str, path: str) -> Optional[str]:
    """
    Checks a given URL for signs of a directory listing.

    Args:
        domain: The domain to check.
        path: The path component of the URL.

    Returns:
        The URL if a directory listing is detected, otherwise None.
    """
    protocols = ["https", "http"]
    headers = {'User-Agent': CONFIG["USER_AGENT"]}
    if not path.startswith('/'):
        path = '/' + path
    for protocol in protocols:
        full_url = urljoin(f"{protocol}://{domain}", path)
        try:
            response = requests.get(
                full_url,
                timeout=CONFIG["TIMEOUT_SECONDS"],
                headers=headers,
                allow_redirects=True
            )
            if response.status_code == 200:
                for pattern in CONFIG["DIRECTORY_LISTING_PATTERNS"]:
                    if pattern in response.text:
                        logger.info(f"[+] Directory Listing Found: {full_url}")
                        return full_url
            elif response.status_code == 403:
                logger.debug(f"[-] Access Forbidden for {full_url}")
            elif response.status_code == 404:
                logger.debug(f"[-] Not Found for {full_url}")
            else:
                logger.debug(f"[-] Unexpected status code {response.status_code} for {full_url}")
        except requests.exceptions.Timeout:
            logger.debug(f"[-] Timeout checking {full_url}")
        except requests.exceptions.ConnectionError:
            logger.debug(f"[-] Connection error checking {full_url}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"[-] Request error checking {full_url}: {e}")
        except Exception as e:
            logger.debug(f"[-] An unexpected error occurred while checking {full_url}: {e}")
    return None

def process_single_target(target: str, temp_file_path: str, threads: int) -> None:
    """
    Processes a single domain (or subdomain) for directory listings.

    Args:
        target: The domain or subdomain to process.
        temp_file_path: Path to the temporary file with all fetched URLs.
        threads: Number of threads to use for checking directory listings.
    """
    logger.info(f"\n[+] Processing target: {target}")
    paths = extract_paths_for_domain(temp_file_path, target)
    if not paths:
        logger.info(f"[-] No unique paths found for {target}.")
        return
    logger.info(f"[+] Found {len(paths)} unique paths for {target}. Checking for directory listings...")
    directory_listings = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {
            executor.submit(check_directory_listing, target, path): path
            for path in paths
        }
        for i, future in enumerate(as_completed(future_to_url), 1):
            url_path = future_to_url[future]
            try:
                result_url = future.result()
                if result_url:
                    directory_listings.append(result_url)
            except Exception as exc:
                logger.debug(f"Generated an exception for {url_path}: {exc}")
            if i % (len(paths) // 10 + 1) == 0 or i == len(paths):
                logger.info(f"  Progress: {i}/{len(paths)} paths checked for {target}")
    if directory_listings:
        logger.info(f"\n[+] Summary of Directory Listings for {target}:")
        for listing in sorted(directory_listings):
            logger.info(f"  - {listing}")
    else:
        logger.info(f"[-] No directory listings found for {target}.")

def process_domains_from_file(file_path: str, threads: int) -> None:
    """
    Reads domains from a file and processes each for directory listings.

    Args:
        file_path: Path to the file containing domains (one per line).
        threads: Number of threads for checking.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors='ignore') as file:
            domains = [line.strip() for line in file if line.strip()]
        if not domains:
            logger.warning(f"[-] No domains found in file: {file_path}")
            return
        logger.info(f"[+] Found {len(domains)} domains in {file_path}. Starting scan...")
        for domain in domains:
            if not re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$", domain):
                logger.warning(f"[-] Invalid domain format for '{domain}'. Skipping.")
                continue
            temp_file_path = fetch_chronoscan_urls(domain)
            if temp_file_path:
                try:
                    process_single_target(domain, temp_file_path, threads)
                finally:
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
            else:
                logger.warning(f"[-] Skipping {domain} due to failure in fetching chronoscan URLs.")
    except FileNotFoundError:
        logger.error(f"[-] Error: Domain list file not found at '{file_path}'")
    except Exception as e:
        logger.error(f"[-] An unexpected error occurred while processing domains from file: {e}")

def auto_discover_and_process(domain: str, threads: int) -> None:
    """
    Automatically discovers subdomains for a given domain and processes them.

    Args:
        domain: The base domain for subdomain discovery.
        threads: Number of threads for checking.
    """
    logger.info(f"[+] Initiating auto-discovery for subdomains of {domain}...")
    temp_file_path = fetch_chronoscan_urls(domain)
    if not temp_file_path:
        logger.error(f"[-] Could not fetch archived URLs for {domain}. Skipping auto-discovery.")
        return
    try:
        subdomains = extract_subdomains(temp_file_path, domain)
        domains_to_process = [domain] + subdomains
        if not domains_to_process:
            logger.info(f"[-] No domains or subdomains found for {domain} after auto-discovery.")
            return
        logger.info(f"[+] Found {len(domains_to_process)} targets (including base domain) to process:")
        for target in domains_to_process:
            logger.info(f"  - {target}")
        for target_domain in domains_to_process:
            process_single_target(target_domain, temp_file_path, threads)
    except Exception as e:
        logger.error(f"[-] An error occurred during auto-discovery and processing for {domain}: {e}")
    finally:
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
            logger.debug(f"Deleted temporary file: {temp_file_path}")

def main() -> None:
    """Main function to parse arguments and run the ArchivEye tool."""
    display_banner()
    parser = argparse.ArgumentParser(
        description="ArchivEye v1.0 - Enhanced Directory Listing Detection Using chronoscan Machine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d", "--domain",
        help="Single target domain to scan (e.g., example.com)"
    )
    group.add_argument(
        "-f", "--file",
        help="File containing a list of domains to scan (one per line)"
    )
    group.add_argument(
        "-auto",
        help="Automatically discover and scan subdomains for the given domain (e.g., example.com)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=CONFIG["DEFAULT_THREADS"],
        help=f"Number of threads for concurrent checks (default: {CONFIG['DEFAULT_THREADS']})"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output (debug messages)"
    )
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")
    domain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")
    if args.domain:
        if not domain_regex.match(args.domain):
            logger.error("[-] Invalid domain format. Please enter a valid domain (e.g., example.com).")
            sys.exit(1)
        temp_file_path = fetch_chronoscan_urls(args.domain)
        if temp_file_path:
            try:
                process_single_target(args.domain, temp_file_path, args.threads)
            finally:
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
        else:
            logger.error(f"[-] Failed to fetch chronoscan URLs for {args.domain}. Cannot proceed.")
    elif args.file:
        process_domains_from_file(args.file, args.threads)
    elif args.auto:
        if not domain_regex.match(args.auto):
            logger.error("[-] Invalid domain format for auto-discovery. Please enter a valid domain (e.g., example.com).")
            sys.exit(1)
        auto_discover_and_process(args.auto, args.threads)
    logger.info("\n[+] Scan completed.")

if __name__ == "__main__":
    main()
