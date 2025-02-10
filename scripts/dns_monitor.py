#!/usr/bin/env python3
import dns.resolver
import whois
import requests
import json
from datetime import datetime, timedelta
import sqlite3
import os
from pathlib import Path

class DNSMonitor:
    def __init__(self):
        self.db_path = Path(__file__).parent.parent / 'data' / 'dns_history.db'
        self.db_path.parent.mkdir(exist_ok=True)
        self.setup_database()

    def setup_database(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY,
                    domain TEXT,
                    record_type TEXT,
                    value TEXT,
                    source TEXT,
                    timestamp DATETIME,
                    UNIQUE(domain, record_type, value, source)
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY,
                    domain TEXT,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    source TEXT,
                    timestamp DATETIME
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS monitor_status (
                    id INTEGER PRIMARY KEY,
                    last_check DATETIME,
                    domains_checked INTEGER,
                    total_records_checked INTEGER
                )
            ''')

    def record_check_status(self, domains_checked, total_records_checked):
        """Record the timestamp and stats of the current check."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute('''
                INSERT INTO monitor_status (last_check, domains_checked, total_records_checked)
                VALUES (?, ?, ?)
            ''', (datetime.now(), domains_checked, total_records_checked))

    def check_dns(self, domain):
        print(f"\n🔍 Checking domain: {domain}")
        changes = []
        current_time = datetime.now()

        # DNS Records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            print(f"  ⚡ Checking {record_type} records...")
            try:
                answers = dns.resolver.resolve(domain, record_type)
                current_values = [str(rdata) for rdata in answers]
                print(f"    ✓ Found {len(current_values)} {record_type} records")
                
                # Compare with stored values
                self.compare_and_store(domain, record_type, current_values, 'DNS', changes)
            except Exception as e:
                print(f"    ❌ Error checking {record_type} records: {e}")

        # WHOIS Information
        print(f"  🌐 Checking WHOIS information...")
        try:
            w = whois.whois(domain)
            whois_data = {
                'registrar': str(w.registrar),
                'expiration_date': str(w.expiration_date),
                'name_servers': str(w.name_servers)
            }
            print(f"    ✓ WHOIS data retrieved successfully")
            self.compare_and_store(domain, 'WHOIS', json.dumps(whois_data), 'WHOIS', changes)
        except Exception as e:
            print(f"    ❌ Error checking WHOIS: {e}")

        # crt.sh Certificate Information
        print(f"  🔒 Checking SSL certificates via crt.sh...")
        try:
            response = requests.get(f'https://crt.sh/?q={domain}&output=json')
            if response.status_code == 200:
                certs = response.json()
                cert_info = [cert['serial_number'] for cert in certs[:5]]  # Store latest 5 certificates
                print(f"    ✓ Found {len(certs)} certificates (storing latest 5)")
                self.compare_and_store(domain, 'CERTS', json.dumps(cert_info), 'crt.sh', changes)
            else:
                print(f"    ⚠️ crt.sh returned status code: {response.status_code}")
        except Exception as e:
            print(f"    ❌ Error checking certificates: {e}")

        return changes

    def compare_and_store(self, domain, record_type, current_values, source, changes):
        with sqlite3.connect(str(self.db_path)) as conn:
            # Get the most recent record
            cursor = conn.execute('''
                SELECT value FROM dns_records 
                WHERE domain = ? AND record_type = ? AND source = ?
                ORDER BY timestamp DESC LIMIT 1
            ''', (domain, record_type, source))
            
            row = cursor.fetchone()
            old_value = row[0] if row else None

            # Convert current_values to string if it's a list
            if isinstance(current_values, list):
                current_values = json.dumps(current_values)

            # If value changed or no previous record exists
            if old_value != current_values:
                print(f"    🔄 Change detected in {record_type} from {source}")
                # Store new record
                conn.execute('''
                    INSERT INTO dns_records (domain, record_type, value, source, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (domain, record_type, current_values, source, datetime.now()))

                # Record the change
                conn.execute('''
                    INSERT INTO changes (domain, change_type, old_value, new_value, source, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (domain, record_type, old_value, current_values, source, datetime.now()))

                changes.append({
                    'domain': domain,
                    'type': record_type,
                    'source': source,
                    'old_value': old_value,
                    'new_value': current_values,
                    'timestamp': datetime.now()
                })
            else:
                print(f"    ✓ No changes in {record_type} from {source}")

if __name__ == '__main__':
    print("🚀 Starting DNS Monitor")
    print("📁 Initializing database...")
    monitor = DNSMonitor()
    print("✅ Database initialized")
    
    # Example domains - replace with your actual domains
    domains = ['example.com', 'google.com']
    print(f"\n📋 Monitoring {len(domains)} domains")
    
    total_records_checked = 0
    for domain in domains:
        changes = monitor.check_dns(domain)
        # Count records checked (A, AAAA, MX, NS, TXT, WHOIS, CERTS)
        total_records_checked += 7
        if changes:
            print(f"\n🔔 Changes detected for {domain}:")
            for change in changes:
                print(f"  • {change['type']} ({change['source']}):")
                print(f"    Old: {change['old_value']}")
                print(f"    New: {change['new_value']}")
        else:
            print(f"\n✅ No changes detected for {domain}")
    
    # Record the check status
    monitor.record_check_status(len(domains), total_records_checked)
    print("\n✨ DNS monitoring complete!")
