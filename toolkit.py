#!/usr/bin/env python3
"""
MRXN1505 Cyber Toolkit
A small, defensive cybersecurity utility collection.
Python 3.8+ | Standard library only
"""

import hashlib
import getpass
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""{BLUE}{BOLD}
╔══════════════════════════════════════════════════╗
║          MRXN1505  /  CYBER TOOLKIT             ║
║       Defensive Security • Terminal Tools       ║
╚══════════════════════════════════════════════════╝{RESET}""")

def pause():
    input(f"\n{DIM}Press Enter to return to menu...{RESET}")

def normalize_url(value):
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL")
    return value

def url_header_audit():
    print(f"\n{CYAN}[ URL SECURITY HEADERS ]{RESET}")
    raw = input("URL (authorized/public site): ").strip()
    try:
        url = normalize_url(raw)
        req = Request(url, headers={"User-Agent": "MRXN1505-CyberToolkit/1.0"})
        try:
            with urlopen(req, timeout=10) as response:
                status = response.status
                headers = response.headers
                final_url = response.geturl()
        except HTTPError as e:
            status, headers, final_url = e.code, e.headers, e.geturl()
        print(f"\nHTTP status : {status}")
        print(f"Final URL   : {final_url}")
        checks = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
        }
        print("\nHeader review:")
        for header, label in checks.items():
            value = headers.get(header)
            if value:
                print(f"  {BLUE}[+]{RESET} {label}: {value}")
            else:
                print(f"  {DIM}[-]{RESET} {label}: not detected")
        if urlparse(final_url).scheme != "https":
            print(f"\n{DIM}Note: final URL is not HTTPS.{RESET}")
    except Exception as e:
        print(f"{DIM}Error: {e}{RESET}")

def dns_lookup():
    print(f"\n{CYAN}[ DNS LOOKUP ]{RESET}")
    host = input("Hostname (e.g. example.com): ").strip()
    if not host or "/" in host or " " in host:
        print("Invalid hostname.")
        return
    try:
        results = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        print(f"\n{host}")
        for ip in results:
            print(f"  {BLUE}•{RESET} {ip}")
    except socket.gaierror as e:
        print(f"Lookup failed: {e}")

def tls_certificate():
    print(f"\n{CYAN}[ TLS CERTIFICATE CHECK ]{RESET}")
    host = input("Hostname: ").strip()
    if not host or "/" in host or " " in host:
        print("Invalid hostname.")
        return
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
        expires = cert.get("notAfter")
        if expires:
            expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            remaining = expiry - datetime.now(timezone.utc)
            print(f"Certificate expires : {expiry.isoformat()}")
            print(f"Days remaining     : {remaining.days}")
            print(f"Status            : {'VALID' if remaining.days >= 0 else 'EXPIRED'}")
        print(f"Subject           : {cert.get('subject', 'N/A')}")
        print(f"Issuer            : {cert.get('issuer', 'N/A')}")
    except Exception as e:
        print(f"TLS check failed: {e}")

def local_network_info():
    print(f"\n{CYAN}[ LOCAL NETWORK INFO ]{RESET}")
    hostname = socket.gethostname()
    print(f"Hostname: {hostname}")
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)
                            if item[4][0] and ":" not in item[4][0]})
        for addr in addresses:
            print(f"IPv4: {addr}")
    except socket.gaierror:
        print("Could not resolve local hostname.")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))  # documentation-only address; no packet sent
            print(f"Default interface IP: {sock.getsockname()[0]}")
    except OSError:
        print("Default interface IP: unavailable")

def file_hash():
    print(f"\n{CYAN}[ FILE HASH CALCULATOR ]{RESET}")
    path = input("File path: ").strip()
    if not os.path.isfile(path):
        print("File not found.")
        return
    algorithms = ("sha256", "sha1", "md5")
    try:
        results = {}
        for algorithm in algorithms:
            digest = hashlib.new(algorithm)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            results[algorithm.upper()] = digest.hexdigest()
        print(f"\nFile: {os.path.basename(path)}")
        for name, value in results.items():
            print(f"{name}: {value}")
    except OSError as e:
        print(f"Error reading file: {e}")

def password_check():
    print(f"\n{CYAN}[ PASSWORD STRENGTH ESTIMATE ]{RESET}")
    print("Input is processed locally and is not transmitted.")
    password = getpass.getpass("Password to evaluate: ")
    if not password:
        print("Empty input.")
        return
    score = 0
    score += len(password) >= 8
    score += len(password) >= 12
    score += len(password) >= 16
    score += any(c.islower() for c in password)
    score += any(c.isupper() for c in password)
    score += any(c.isdigit() for c in password)
    score += any(not c.isalnum() for c in password)
    common = {"password", "password123", "12345678", "qwerty", "admin", "letmein"}
    label = "WEAK"
    if password.lower() in common:
        score = 0
    elif score >= 6:
        label = "STRONG"
    elif score >= 4:
        label = "MODERATE"
    print(f"Assessment: {label}")
    print("Suggestion: use a unique passphrase, ideally 16+ characters.")
    del password

def menu():
    while True:
        banner()
        print(f"""{WHITE}
 [1] URL security-header review
 [2] DNS lookup
 [3] TLS certificate expiry
 [4] Local network information
 [5] File hash calculator
 [6] Password strength estimate
 [0] Exit
{RESET}""")
        choice = input(f"{CYAN}mrxn1505@toolkit{RESET} {BLUE}~>{RESET} ").strip()
        actions = {
            "1": url_header_audit,
            "2": dns_lookup,
            "3": tls_certificate,
            "4": local_network_info,
            "5": file_hash,
            "6": password_check,
        }
        if choice == "0":
            print("Goodbye.")
            return
        action = actions.get(choice)
        if action:
            action()
            pause()
        else:
            print("Invalid option.")
            pause()

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
        sys.exit(0)
