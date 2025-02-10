#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import json

class UpdateHandler:
    def __init__(self):
        self.db_path = Path(__file__).parent.parent / 'data' / 'dns_history.db'
        self.template_path = Path(__file__).parent.parent / 'dashboard' / 'dns_table.html'
        self.output_path = self.template_path
        self.log_dir = Path(__file__).parent.parent / 'data' / 'logs'
        self.log_dir.mkdir(exist_ok=True)

    def get_recent_changes(self, days=14):
        print(f"📅 Fetching changes from the last {days} days...")
        cutoff_date = datetime.now() - timedelta(days=days)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute('''
                SELECT 
                    changes.domain,
                    changes.change_type,
                    changes.old_value,
                    changes.new_value,
                    changes.source,
                    changes.timestamp,
                    (SELECT COUNT(*) FROM changes c2 
                     WHERE c2.domain = changes.domain 
                     AND c2.timestamp > ?) as change_frequency
                FROM changes
                WHERE changes.timestamp > ?
                ORDER BY changes.timestamp DESC
            ''', (cutoff_date, cutoff_date))
            changes = cursor.fetchall()
            print(f"✓ Found {len(changes)} changes")
            return changes

    def get_external_links(self, domain, record_type):
        """Generate relevant external links for the domain and record type."""
        links = []
        if record_type == 'A' or record_type == 'AAAA':
            links.extend([
                ('VirusTotal', f'https://www.virustotal.com/gui/domain/{domain}'),
                ('SecurityTrails', f'https://securitytrails.com/domain/{domain}/dns'),
                ('DNSDumpster', f'https://dnsdumpster.com/?query={domain}')
            ])
        elif record_type == 'CERTS':
            links.extend([
                ('crt.sh', f'https://crt.sh/?q={domain}'),
                ('Censys', f'https://search.censys.io/certificates?q=names%3A{domain}')
            ])
        elif record_type == 'WHOIS':
            links.extend([
                ('WHOIS', f'https://whois.domaintools.com/{domain}'),
                ('ICANN Lookup', f'https://lookup.icann.org/lookup?q={domain}')
            ])
        return links

    def format_change_html(self, change):
        domain, change_type, old_value, new_value, source, timestamp, change_frequency = change
        timestamp_dt = datetime.fromisoformat(timestamp)
        age_hours = (datetime.now() - timestamp_dt).total_seconds() / 3600
        
        urgency_class = ''
        urgency_badge = ''
        if age_hours <= 48:
            urgency_class = 'bg-red-100'
            urgency_badge = '<span class="px-2 py-1 text-xs font-bold text-white bg-red-500 rounded-full">New</span>'
        elif age_hours <= 336:  # 14 days
            urgency_class = 'bg-yellow-50'
            urgency_badge = '<span class="px-2 py-1 text-xs font-bold text-white bg-yellow-500 rounded-full">Recent</span>'

        # Format values for better readability
        try:
            old_value = json.loads(old_value) if old_value else None
            new_value = json.loads(new_value) if new_value else None
        except (json.JSONDecodeError, TypeError):
            pass

        # Generate diff for complex values
        if isinstance(old_value, (list, dict)) and isinstance(new_value, (list, dict)):
            added = [x for x in new_value if x not in (old_value or [])]
            removed = [x for x in (old_value or []) if x not in new_value]
            value_diff = f'''
                <div class="space-y-2">
                    {'<div class="text-red-600"><strong>Removed:</strong> ' + ', '.join(removed) + '</div>' if removed else ''}
                    {'<div class="text-green-600"><strong>Added:</strong> ' + ', '.join(added) + '</div>' if added else ''}
                </div>
            '''
        else:
            value_diff = f'''
                <div class="space-y-2">
                    <div class="text-red-600 line-through"><strong>Old:</strong> {old_value}</div>
                    <div class="text-green-600"><strong>New:</strong> {new_value}</div>
                </div>
            '''

        # Generate external links
        links = self.get_external_links(domain, change_type)
        links_html = ''.join([
            f'<a href="{url}" target="_blank" class="inline-flex items-center px-2 py-1 text-xs font-medium text-gray-700 bg-gray-100 rounded hover:bg-gray-200">'
            f'{name} <svg class="w-3 h-3 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>'
            f'</a>'
            for name, url in links
        ])

        return f'''
        <div class="p-4 mb-4 rounded-lg {urgency_class} border border-gray-200">
            <div class="flex justify-between items-center">
                <div class="flex items-center space-x-2">
                    <h3 class="text-lg font-semibold">{domain}</h3>
                    {urgency_badge}
                    <span class="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 rounded">
                        {change_frequency} changes in 14 days
                    </span>
                </div>
                <span class="text-sm text-gray-500">{timestamp}</span>
            </div>
            <div class="mt-2 space-y-2">
                <div class="flex items-center space-x-2">
                    <span class="px-2 py-1 text-xs font-medium text-blue-700 bg-blue-100 rounded">{change_type}</span>
                    <span class="px-2 py-1 text-xs font-medium text-purple-700 bg-purple-100 rounded">{source}</span>
                </div>
                {value_diff}
                <div class="mt-3 flex flex-wrap gap-2">
                    {links_html}
                </div>
            </div>
        </div>
        '''

    def generate_json_log(self, changes):
        """Generate a JSON log file for the changes."""
        log_file = self.log_dir / f'dns_changes_{datetime.now().strftime("%Y%m")}.json'
        
        # Load existing log if it exists
        existing_data = []
        if log_file.exists():
            with open(log_file, 'r') as f:
                existing_data = json.load(f)

        # Format new changes
        new_entries = []
        for change in changes:
            domain, change_type, old_value, new_value, source, timestamp, change_frequency = change
            try:
                old_value = json.loads(old_value) if old_value else None
                new_value = json.loads(new_value) if new_value else None
            except (json.JSONDecodeError, TypeError):
                pass

            new_entries.append({
                'timestamp': timestamp,
                'domain': domain,
                'type': change_type,
                'source': source,
                'old_value': old_value,
                'new_value': new_value,
                'change_frequency': change_frequency
            })

        # Combine and save
        all_entries = new_entries + existing_data
        with open(log_file, 'w') as f:
            json.dump(all_entries, f, indent=2)
        
        print(f"📝 Updated JSON log at {log_file}")
        return log_file

    def get_dns_statistics(self):
        """Get overall DNS monitoring statistics."""
        with sqlite3.connect(str(self.db_path)) as conn:
            # Get total changes in last 24h, 7d, and 14d
            stats = {}
            for days, label in [(1, '24h'), (7, '7d'), (14, '14d')]:
                cutoff = datetime.now() - timedelta(days=days)
                cursor = conn.execute('''
                    SELECT COUNT(*) as total,
                           COUNT(DISTINCT domain) as domains,
                           COUNT(DISTINCT change_type) as types
                    FROM changes 
                    WHERE timestamp > ?
                ''', (cutoff,))
                row = cursor.fetchone()
                stats[label] = {
                    'total_changes': row[0],
                    'affected_domains': row[1],
                    'change_types': row[2]
                }

            # Get most active domains
            cursor = conn.execute('''
                SELECT domain, COUNT(*) as changes
                FROM changes
                WHERE timestamp > ?
                GROUP BY domain
                ORDER BY changes DESC
                LIMIT 5
            ''', (datetime.now() - timedelta(days=14),))
            stats['most_active'] = cursor.fetchall()

            # Get most common change types
            cursor = conn.execute('''
                SELECT change_type, COUNT(*) as count
                FROM changes
                WHERE timestamp > ?
                GROUP BY change_type
                ORDER BY count DESC
            ''', (datetime.now() - timedelta(days=14),))
            stats['change_types'] = cursor.fetchall()

            return stats

    def get_last_check_info(self):
        """Get information about the last DNS check."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute('''
                SELECT last_check, domains_checked, total_records_checked 
                FROM monitor_status 
                ORDER BY last_check DESC LIMIT 1
            ''')
            row = cursor.fetchone()
            if row:
                return {
                    'timestamp': datetime.fromisoformat(row[0]),
                    'domains_checked': row[1],
                    'records_checked': row[2]
                }
            return None

    def format_statistics_html(self, stats):
        """Format DNS statistics into HTML."""
        # Get last check information
        last_check = self.get_last_check_info()
        
        # Get changes in the last 2 weeks
        two_weeks_ago = datetime.now() - timedelta(days=14)
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT 
                    COUNT(CASE WHEN change_type = 'dns' THEN 1 END) as dns_changes,
                    COUNT(CASE WHEN change_type = 'whois' THEN 1 END) as whois_changes,
                    COUNT(CASE WHEN change_type = 'crt' THEN 1 END) as crt_changes,
                    MAX(timestamp) as last_run
                FROM changes 
                WHERE timestamp > ?
            ''', (two_weeks_ago,))
            changes = cursor.fetchone()
        
        # Format the values
        if changes and changes['last_run']:
            try:
                last_run_dt = datetime.fromisoformat(changes['last_run'])
                last_run = last_run_dt.strftime('%m/%d %H:%M')
            except:
                last_run = changes['last_run']
            dns_changes = changes['dns_changes'] or 0
            whois_changes = changes['whois_changes'] or 0
            crt_changes = changes['crt_changes'] or 0
        else:
            last_run = datetime.now().strftime('%m/%d %H:%M')
            dns_changes = 0
            whois_changes = 0
            crt_changes = 0
            
        # Create stat cards
        stat_cards = f'''
        <!-- Domain Section -->
        <nav class="mt-8 bg-white shadow rounded-lg">
            <div class="px-3 py-2 bg-gray-50">
                <div class="flex justify-between items-center">
                    <div class="flex items-center space-x-4">
                        <h2 class="text-base font-semibold leading-7 text-gray-900">02 DNS Records</h2>
                        <div class="flex items-center">
                            <span id="scanStatusIndicator" class="h-2.5 w-2.5 rounded-full bg-green-400"></span>
                            <span id="lastScanTime" class="ml-2 text-sm text-gray-500">
                                {last_check['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if last_check else 'Never'}
                            </span>
                        </div>
                    </div>
                    <div>
                        <span id="lastScanStats" class="text-sm text-gray-500">
                            {f"{last_check['domains_checked']} domains, {last_check['records_checked']} records" if last_check else "No data"}
                        </span>
                    </div>
                </div>
            </div>
        </nav>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 mt-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Last 24 Hours</h3>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="text-sm text-gray-500">Changes</p>
                        <p class="text-2xl font-bold text-blue-600">{stats['24h']['total_changes']}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-500">Domains</p>
                        <p class="text-2xl font-bold text-green-600">{stats['24h']['affected_domains']}</p>
                    </div>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Last 7 Days</h3>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="text-sm text-gray-500">Changes</p>
                        <p class="text-2xl font-bold text-blue-600">{stats['7d']['total_changes']}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-500">Domains</p>
                        <p class="text-2xl font-bold text-green-600">{stats['7d']['affected_domains']}</p>
                    </div>
                </div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Last 14 Days</h3>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <p class="text-sm text-gray-500">Changes</p>
                        <p class="text-2xl font-bold text-blue-600">{stats['14d']['total_changes']}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-500">Domains</p>
                        <p class="text-2xl font-bold text-green-600">{stats['14d']['affected_domains']}</p>
                    </div>
                </div>
            </div>
        </div>
        '''

        # Create activity overview
        most_active_domains = '\n'.join([
            f'<div class="flex justify-between items-center py-2">'
            f'<span class="text-gray-900">{domain}</span>'
            f'<span class="px-2 py-1 text-sm text-blue-700 bg-blue-100 rounded-full">{count} changes</span>'
            f'</div>'
            for domain, count in stats['most_active']
        ])

        change_type_stats = '\n'.join([
            f'<div class="flex justify-between items-center py-2">'
            f'<span class="text-gray-900">{type_}</span>'
            f'<span class="px-2 py-1 text-sm text-purple-700 bg-purple-100 rounded-full">{count}</span>'
            f'</div>'
            for type_, count in stats['change_types']
        ])

        activity_overview = f'''
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Most Active Domains</h3>
                <div class="divide-y divide-gray-200">
                    {most_active_domains}
                </div>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold text-gray-900 mb-4">Change Type Distribution</h3>
                <div class="divide-y divide-gray-200">
                    {change_type_stats}
                </div>
            </div>
        </div>
        '''

        # Create preview section
        preview_section = f'''
        <div class="bg-gray-50 py-8">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <h2 class="text-2xl font-bold text-gray-900 mb-6">DNS Monitoring Overview</h2>
                {stat_cards}
                {activity_overview}
            </div>
        </div>
        '''

        return preview_section

    def update_website(self):
        """Update the website with recent changes and statistics."""
        print("\n🌐 Starting website update process...")
        
        # Get recent changes
        print("📊 Retrieving recent changes...")
        changes = self.get_recent_changes()
        
        # Get statistics
        print("📈 Generating DNS statistics...")
        stats = self.get_dns_statistics()
        
        # Get changes in the last 2 weeks
        two_weeks_ago = datetime.now() - timedelta(days=14)
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT 
                    COUNT(CASE WHEN change_type = 'dns' THEN 1 END) as dns_changes,
                    COUNT(CASE WHEN change_type = 'whois' THEN 1 END) as whois_changes,
                    COUNT(CASE WHEN change_type = 'crt' THEN 1 END) as crt_changes,
                    MAX(timestamp) as last_run
                FROM changes 
                WHERE timestamp > ?
            ''', (two_weeks_ago,))
            preview_changes = cursor.fetchone()
        
        # Format preview values
        if preview_changes and preview_changes['last_run']:
            try:
                last_run_dt = datetime.fromisoformat(preview_changes['last_run'])
                last_run = last_run_dt.strftime('%m/%d %H:%M')
            except:
                last_run = preview_changes['last_run']
            dns_changes = preview_changes['dns_changes'] or 0
            whois_changes = preview_changes['whois_changes'] or 0
            crt_changes = preview_changes['crt_changes'] or 0
        else:
            last_run = datetime.now().strftime('%m/%d %H:%M')
            dns_changes = 0
            whois_changes = 0
            crt_changes = 0
        
        # Read template
        print("📄 Reading template file...")
        with open(self.template_path, 'r') as f:
            content = f.read()
        
        # Format changes in HTML
        print("🎨 Formatting changes in HTML...")
        if changes:
            print(f"🔔 Adding notification badge for {len(changes)} recent changes")
            
        # Replace the preview section values
        content = content.replace('id="preview-last-run">Last run:', f'id="preview-last-run">Last run: {last_run}')
        content = content.replace('id="preview-dns">DNS: 0 changes', f'id="preview-dns">DNS: {dns_changes} changes')
        content = content.replace('id="preview-whois">WHOIS: 0 changes', f'id="preview-whois">WHOIS: {whois_changes} changes')
        content = content.replace('id="preview-crtsh">CRT.sh: 0 changes', f'id="preview-crtsh">CRT.sh: {crt_changes} changes')
        
        # Write updated content
        print("📝 Writing updated content to file...")
        with open(self.template_path, 'w') as f:
            f.write(content)
            
        print("✨ Website update complete!")

if __name__ == '__main__':
    print("🚀 Starting DNS Update Handler")
    handler = UpdateHandler()
    handler.update_website()
