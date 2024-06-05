"""
Version: 1.1
Date: 2024-06-05
Author: Virgil Vaduva
License: Unlicensed (https://unlicense.org)
"""

import requests
from bs4 import BeautifulSoup
import hashlib
import base64
from urllib.parse import urlparse
from tabulate import tabulate
import secrets
import concurrent.futures
import threading

def ensure_scheme(url):
    """Ensure the URL starts with http:// or https://, default to https:// if no scheme is provided."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def fetch_url(url, index):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        print(f"Parsing Asset {index}: {url}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        return index, url, response.content, None
    except requests.RequestException as e:
        error_msg = e.__cause__ if e.__cause__ else e
        print(f"Failed parsing {url} due to {error_msg}")
        return index, url, None, error_msg

def extract_resources(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script', src=True)
    styles = soup.find_all('link', rel='stylesheet')
    return scripts + styles

def generate_hash(content):
    hasher = hashlib.sha256()
    hasher.update(content)
    return base64.b64encode(hasher.digest()).decode('utf-8')

def get_resource_hashes(resources, base_url):
    asset_hashes = {}
    local_hashes = {}
    lock = threading.Lock()

    def process_resource(index, resource):
        src = resource.get('src') or resource.get('href')
        full_url = requests.compat.urljoin(base_url, src)
        index, url, content, error = fetch_url(full_url, index)
        display_src = f"{index}: {url[:80]}" if len(url) > 80 else f"{index}: {url}"
        if content:
            resource_hash = generate_hash(content)
            domain = urlparse(url).netloc
            with lock:
                if domain == urlparse(base_url).netloc:
                    if domain not in local_hashes:
                        local_hashes[domain] = []
                    local_hashes[domain].append(resource_hash)
                else:
                    if domain not in asset_hashes:
                        asset_hashes[domain] = []
                    asset_hashes[domain].append(resource_hash)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_resource, index, resource) for index, resource in enumerate(resources, start=1)]
        concurrent.futures.wait(futures)

    return local_hashes, asset_hashes

def create_csp_policy(local_hashes, asset_hashes, nonce=None):
    policy = "Content-Security-Policy: script-src 'self' "
    if nonce:
        policy += f"'nonce-{nonce}' 'strict-dynamic' "
    for domain, hashes in local_hashes.items():
        policy += " ".join([f"'sha256-{h}'" for h in hashes]) + " "
    for domain, hashes in asset_hashes.items():
        policy += f"https://{domain} " + " ".join([f"'sha256-{h}'" for h in hashes]) + " "
    return policy.strip()

def display_tables(local_hashes, asset_hashes):
    local_table = [["Local Domain", "Hashes"]]
    third_party_table = [["Third-Party Domain", "Hashes"]]
    for domain, hashes in local_hashes.items():
        local_table.append([domain, "\n".join([f"sha256-{h}" for h in hashes])])
    for domain, hashes in asset_hashes.items():
        third_party_table.append([domain, "\n".join([f"sha256-{h}" for h in hashes])])

    if local_hashes:
        print("\nLocal Domains and Asset Hashes:")
        print(tabulate(local_table, headers="firstrow", tablefmt="grid"))

    if asset_hashes:
        print("\nThird-Party Domains and Asset Hashes:")
        print(tabulate(third_party_table, headers="firstrow", tablefmt="grid"))

def main(url):
    url = ensure_scheme(url)  # Ensure URL has a scheme
    print(f"This script will perform an unthrottled scan of the URL {url}. Do you want to continue? (Yes/No)")
    choice = input().strip().lower()
    if choice != 'yes':
        print("Scan aborted.")
        return

    print(f"Initiating scan of {url}")
    response = fetch_url(url, 1)  # Initial scan starts with index 1
    if response[2]:  # Check if the initial fetch was successful
        resources = extract_resources(response[2])
        local_hashes, asset_hashes = get_resource_hashes(resources, url)
        nonce = secrets.token_urlsafe(16)  # Generate a secure random nonce
        standard_policy = create_csp_policy(local_hashes, asset_hashes)
        nonce_policy = create_csp_policy(local_hashes, asset_hashes, nonce)
        display_tables(local_hashes, asset_hashes)
        print("\nStandard CSP Policy; copy and paste the line below into your web server or hosting provider Content-Security-Policy security headers directive:")
        print("--------------------------------------------------------------")
        print(standard_policy)
        print("--------------------------------------------------------------")

        print("\nWarning: If you don't know what you are doing, do not update your CSP directives using a nonce policy. The JavaScript scripts running on the site must be updated to accommodate nonces. This includes script-src 'nonce-{random}' in your CSP header, which means that only <script> elements with matching nonce values will execute. This also includes the strict-dynamic keyword, which may not be supported by older browser versions.\nHere is an example of how to add a nonce to your script tags:\n")
        print('<script nonce="random_nonce_value">')
        print('    // Your inline JavaScript code here')
        print('</script>\n')
        print("\nCSP Policy with Nonce; copy and paste the line below into your web server or hosting provider Content-Security-Policy security headers directive:")
        print("--------------------------------------------------------------")
        print(nonce_policy)
        print("--------------------------------------------------------------")
        print("Scan complete.")

if __name__ == "__main__":
    url = input("Enter the URL: ")
    main(url)
