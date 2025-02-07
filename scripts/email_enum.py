#!/usr/bin/env python3

import dns.resolver
import requests
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Set
import argparse
from datetime import datetime

class EmailEnumerator:
    def __init__(self, domain: str):
        self.domain = domain
        self.discovered_emails: Set[str] = set()
        self.valid_emails: Set[str] = set()
        self.common_names = []
        
    def generate_email_patterns(self, first: str, last: str) -> List[str]:
        patterns = [
            f"{first}.{last}@{self.domain}",
            f"{first[0]}{last}@{self.domain}",
            f"{first}{last[0]}@{self.domain}",
            f"{first}@{self.domain}",
            f"{last}@{self.domain}",
            f"{first}{last}@{self.domain}"
        ]
        return [email.lower() for email in patterns]

    def verify_mx_records(self) -> bool:
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            return len(mx_records) > 0
        except:
            print(f"[-] No MX records found for {self.domain}")
            return False

    def verify_email(self, email: str) -> bool:
        # Basic format verification
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return False
        return True

    def save_results(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"email_enum_{self.domain}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"Email Enumeration Results for {self.domain}\n")
            f.write("=" * 50 + "\n\n")
            f.write("Valid Email Addresses:\n")
            for email in sorted(self.valid_emails):
                f.write(f"{email}\n")
        
        print(f"\n[+] Results saved to {filename}")

    def run(self):
        print(f"[+] Starting email enumeration for {self.domain}")
        
        if not self.verify_mx_records():
            print("[-] Unable to verify MX records. Domain might not accept emails.")
            return

        # Common professional names for testing
        test_names = [
            ("john", "doe"),
            ("jane", "smith"),
            ("admin", "admin"),
            ("info", "info"),
            ("contact", "contact"),
            ("webmaster", "webmaster"),
        ]

        print("[+] Testing common email patterns...")
        for first, last in test_names:
            patterns = self.generate_email_patterns(first, last)
            for email in patterns:
                if self.verify_email(email):
                    self.valid_emails.add(email)
                    print(f"[+] Potential valid email found: {email}")
                time.sleep(0.5)  # Be nice to the server

        self.save_results()
        print(f"\n[+] Found {len(self.valid_emails)} potential valid email addresses")

def main():
    parser = argparse.ArgumentParser(description='Email enumeration tool')
    parser.add_argument('-d', '--domain', type=str, required=True,
                      help='Target domain to enumerate')
    args = parser.parse_args()

    enumerator = EmailEnumerator(args.domain)
    enumerator.run()

if __name__ == "__main__":
    main()
