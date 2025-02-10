#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

class MacDeviceScanner:
    """Scanner for macOS security settings based on CIS benchmarks"""
    
    def __init__(self):
        """Initialize scanner"""
        self.today = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.reports_dir = Path('reports')
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize report data
        self.report_data = {
            'sections': {},
            'system_info': {}
        }
        
        # Initialize system info
        self._init_system_info()
        
        # Initialize sections
        self._init_sections()
    
    def _init_system_info(self):
        """Initialize system information"""
        self.report_data['system_info'] = {
            'ProductName': 'macOS',
            'ProductVersion': self._get_os_version(),
            'BuildVersion': self._get_build_version()
        }
    
    def _init_sections(self):
        """Initialize report sections"""
        self.report_data['sections'] = {
            'system_security': None,
            'password_policy': None,
            'screen_saver': None,
            'network_security': None,
            'sharing_settings': None,
            'software_updates': None,
            'logging_auditing': None
        }
    
    def _safe_run_command(self, cmd: List[str]) -> str:
        """Run command safely and handle errors gracefully"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                print(f"Warning: Command {' '.join(cmd)} failed: {result.stderr}")
                return ""
            return result.stdout.strip()
        except Exception as e:
            print(f"Error running command {' '.join(cmd)}: {str(e)}")
            return ""

    def _get_os_version(self) -> str:
        """Get macOS version"""
        try:
            result = self._safe_run_command(['sw_vers', '-productVersion'])
            return result.strip() or 'Unknown'
        except:
            return 'Unknown'
    
    def _get_build_version(self) -> str:
        """Get macOS build version"""
        try:
            result = self._safe_run_command(['sw_vers', '-buildVersion'])
            return result.strip() or 'Unknown'
        except:
            return 'Unknown'
    
    def check_prerequisites(self):
        """Display scanner information"""
        print("\n=== Security Scanner Information ===")
        print("This scanner will check your system security settings and may require:")
        print("1. Administrator (sudo) privileges for some checks")
        print("2. Keychain access for certificate and security checks\n")
        
        print("The following checks will be performed:")
        print("- System Security")
        print("- Password Policy")
        print("- Screen Saver Security")
        print("- Network Security")
        print("- Sharing Settings")
        print("- Software Updates")
        print("- Logging and Auditing\n")
    
    def get_installed_apps(self) -> List[Dict]:
        """Get list of installed applications and their versions"""
        apps = []
        
        # Check /Applications directory
        for app in Path("/Applications").glob("*.app"):
            info_plist = app / "Contents/Info.plist"
            if info_plist.exists():
                try:
                    with open(info_plist, 'rb') as f:
                        plist_data = plistlib.load(f)
                        apps.append({
                            'name': app.name.replace('.app', ''),
                            'version': plist_data.get('CFBundleShortVersionString', 'Unknown'),
                            'path': str(app)
                        })
                except Exception as e:
                    print(f"Error reading {info_plist}: {e}")
        
        return apps

    def check_cis_compliance(self) -> List[Dict]:
        """Perform comprehensive CIS benchmark checks"""
        checks = []
        print("\nRunning CIS Benchmark Checks...")
        
        def run_command(cmd):
            """Helper function to run commands with error handling"""
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.stdout.strip(), result.returncode == 0
            except Exception as e:
                print(f"Error running command {' '.join(cmd)}: {e}")
                return str(e), False
        
        # 1. System Security Configuration
        print("\n1. System Security Configuration:")
        
        # 1.1 FileVault encryption
        stdout, success = run_command(['fdesetup', 'status'])
        is_filevault_on = 'FileVault is On' in stdout
        checks.append({
            'name': '1.1 FileVault Encryption',
            'status': is_filevault_on,
            'score': 5 if is_filevault_on else 0,
            'details': stdout
        })
        print(f"✓ FileVault Status: {'Enabled' if is_filevault_on else 'Disabled'}")
        
        # 1.2 System Integrity Protection
        stdout, success = run_command(['csrutil', 'status'])
        is_sip_enabled = 'enabled' in stdout.lower()
        checks.append({
            'name': '1.2 System Integrity Protection',
            'status': is_sip_enabled,
            'score': 5 if is_sip_enabled else 0,
            'details': stdout
        })
        print(f"✓ SIP Status: {'Enabled' if is_sip_enabled else 'Disabled'}")
        
        # 1.3 Gatekeeper
        stdout, success = run_command(['spctl', '--status'])
        is_gatekeeper_enabled = 'assessments enabled' in stdout.lower()
        checks.append({
            'name': '1.3 Gatekeeper',
            'status': is_gatekeeper_enabled,
            'score': 3 if is_gatekeeper_enabled else 0,
            'details': 'Gatekeeper is enabled' if is_gatekeeper_enabled else 'Gatekeeper is disabled'
        })
        print(f"✓ Gatekeeper: {'Enabled' if is_gatekeeper_enabled else 'Disabled'}")
        
        # 2. Network Configuration
        print("\n2. Network Configuration:")
        
        # 2.1 Firewall Status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'])
        try:
            is_firewall_enabled = int(stdout) > 0
        except:
            is_firewall_enabled = False
        checks.append({
            'name': '2.1 Firewall',
            'status': is_firewall_enabled,
            'score': 3 if is_firewall_enabled else 0,
            'details': 'Firewall is enabled' if is_firewall_enabled else 'Firewall is disabled'
        })
        print(f"✓ Firewall: {'Enabled' if is_firewall_enabled else 'Disabled'}")
        
        # 2.2 Remote Login Status
        stdout, success = run_command(['systemsetup', '-getremotelogin'])
        is_remote_login_off = 'Off' in stdout
        checks.append({
            'name': '2.2 Remote Login (SSH)',
            'status': is_remote_login_off,
            'score': 2 if is_remote_login_off else 0,
            'details': stdout
        })
        print(f"✓ Remote Login: {'Disabled' if is_remote_login_off else 'Enabled'}")
        
        # 2.3 Network Time
        stdout, success = run_command(['systemsetup', '-getnetworktimeserver'])
        is_time_sync_on = 'On' in stdout
        checks.append({
            'name': '2.3 Network Time',
            'status': is_time_sync_on,
            'score': 1 if is_time_sync_on else 0,
            'details': stdout
        })
        print(f"✓ Network Time: {'Enabled' if is_time_sync_on else 'Disabled'}")
        
        # 3. User Security
        print("\n3. User Security:")
        
        # 3.1 Guest Account
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled'])
        is_guest_disabled = success and '0' in stdout
        checks.append({
            'name': '3.1 Guest Account',
            'status': is_guest_disabled,
            'score': 2 if is_guest_disabled else 0,
            'details': 'Guest account is disabled' if is_guest_disabled else 'Guest account is enabled'
        })
        print(f"✓ Guest Account: {'Disabled' if is_guest_disabled else 'Enabled'}")
        
        # 3.2 Automatic Login
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.loginwindow', 'autoLoginUser'])
        is_autologin_disabled = not success or 'does not exist' in stdout
        checks.append({
            'name': '3.2 Automatic Login',
            'status': is_autologin_disabled,
            'score': 2 if is_autologin_disabled else 0,
            'details': 'Automatic login is disabled' if is_autologin_disabled else 'Automatic login is enabled'
        })
        print(f"✓ Automatic Login: {'Disabled' if is_autologin_disabled else 'Enabled'}")
        
        # 3.3 Password Requirements
        stdout, success = run_command(['pwpolicy', '-getaccountpolicies'])
        has_password_policy = success and 'minChars' in stdout
        checks.append({
            'name': '3.3 Password Policy',
            'status': has_password_policy,
            'score': 3 if has_password_policy else 0,
            'details': 'Password policy is configured' if has_password_policy else 'No password policy found'
        })
        print(f"✓ Password Policy: {'Configured' if has_password_policy else 'Not Configured'}")
        
        # 3.4 Screen Saver Password
        stdout, success = run_command(['defaults', 'read', 'com.apple.screensaver', 'askForPassword'])
        is_screensaver_password_enabled = success and '1' in stdout
        checks.append({
            'name': '3.4 Screen Saver Password',
            'status': is_screensaver_password_enabled,
            'score': 2 if is_screensaver_password_enabled else 0,
            'details': 'Screen saver password is enabled' if is_screensaver_password_enabled else 'Screen saver password is disabled'
        })
        print(f"✓ Screen Saver Password: {'Enabled' if is_screensaver_password_enabled else 'Disabled'}")
        
        # 4. System Updates
        print("\n4. System Updates:")
        
        # 4.1 Auto Update Status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticCheckEnabled'])
        try:
            is_autoupdate_enabled = int(stdout) == 1
        except:
            is_autoupdate_enabled = False
        checks.append({
            'name': '4.1 Automatic Updates',
            'status': is_autoupdate_enabled,
            'score': 3 if is_autoupdate_enabled else 0,
            'details': 'Automatic updates enabled' if is_autoupdate_enabled else 'Automatic updates disabled'
        })
        print(f"✓ Auto Updates: {'Enabled' if is_autoupdate_enabled else 'Disabled'}")
        
        # 4.2 App Store Updates
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.commerce', 'AutoUpdate'])
        try:
            is_appstore_autoupdate = int(stdout) == 1
        except:
            is_appstore_autoupdate = False
        checks.append({
            'name': '4.2 App Store Updates',
            'status': is_appstore_autoupdate,
            'score': 2 if is_appstore_autoupdate else 0,
            'details': 'App Store auto-updates enabled' if is_appstore_autoupdate else 'App Store auto-updates disabled'
        })
        print(f"✓ App Store Updates: {'Enabled' if is_appstore_autoupdate else 'Disabled'}")
        
        # 5. Privacy & Analytics
        print("\n5. Privacy & Analytics:")
        
        # 5.1 Analytics Data
        stdout, success = run_command(['defaults', 'read', '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist', 'AutoSubmit'])
        is_analytics_disabled = not success or 'does not exist' in stdout or '0' in stdout
        checks.append({
            'name': '5.1 Analytics Data Collection',
            'status': is_analytics_disabled,
            'score': 1 if is_analytics_disabled else 0,
            'details': 'Analytics data collection is disabled' if is_analytics_disabled else 'Analytics data collection is enabled'
        })
        print(f"✓ Analytics Collection: {'Disabled' if is_analytics_disabled else 'Enabled'}")
        
        # 5.2 Location Services
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.locationd', 'LocationServicesEnabled'])
        try:
            is_location_services_disabled = int(stdout) == 0
        except:
            is_location_services_disabled = True
        checks.append({
            'name': '5.2 Location Services',
            'status': is_location_services_disabled,
            'score': 1 if is_location_services_disabled else 0,
            'details': 'Location services are disabled' if is_location_services_disabled else 'Location services are enabled'
        })
        print(f"✓ Location Services: {'Disabled' if is_location_services_disabled else 'Enabled'}")
        
        # 6. Disk Encryption
        print("\n6. Disk Encryption:")
        
        # 6.1 Time Machine Encryption
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.TimeMachine', 'AutoBackup'])
        is_timemachine_enabled = success and '1' in stdout
        if is_timemachine_enabled:
            stdout, success = run_command(['tmutil', 'destinationinfo'])
            is_timemachine_encrypted = 'Encrypted = 1' in stdout
        else:
            is_timemachine_encrypted = False
        checks.append({
            'name': '6.1 Time Machine Encryption',
            'status': is_timemachine_encrypted,
            'score': 3 if is_timemachine_encrypted else 0,
            'details': 'Time Machine backups are encrypted' if is_timemachine_encrypted else 'Time Machine encryption not configured'
        })
        print(f"✓ Time Machine Encryption: {'Enabled' if is_timemachine_encrypted else 'Not Configured'}")
        
        # 7. Audit Logging
        print("\n7. Audit Logging:")
        
        # 7.1 Security Auditing
        stdout, success = run_command(['auditd', '-s'])
        is_auditing_enabled = success
        checks.append({
            'name': '7.1 Security Auditing',
            'status': is_auditing_enabled,
            'score': 3 if is_auditing_enabled else 0,
            'details': 'Security auditing is enabled' if is_auditing_enabled else 'Security auditing is disabled'
        })
        print(f"✓ Security Auditing: {'Enabled' if is_auditing_enabled else 'Disabled'}")
        
        # Calculate total score
        total_score = sum(check['score'] for check in checks)
        max_score = 40  # Sum of all possible scores
        security_score = (total_score / max_score) * 100
        
        print(f"\nSecurity Score: {security_score:.1f}%")
        return checks

    def check_network_security(self) -> List[Dict]:
        """Check network security configuration and open ports"""
        print("\nChecking Network Security...")
        results = []
        
        def run_command(cmd):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.stdout.strip(), result.returncode == 0
            except Exception as e:
                return str(e), False

        # Check listening ports
        stdout, success = run_command(['lsof', '-i', '-P', '-n'])
        if success:
            listening_ports = [line for line in stdout.split('\n') if 'LISTEN' in line]
            results.append({
                'check_type': 'network',
                'name': 'Open Ports',
                'status': len(listening_ports) < 10,  # Arbitrary threshold
                'details': f"Found {len(listening_ports)} listening ports:\n" + '\n'.join(listening_ports[:5])
            })
            print(f"✓ Found {len(listening_ports)} listening ports")

        # Check sharing services
        stdout, success = run_command(['sharing', '-l'])
        if success:
            active_shares = [line for line in stdout.split('\n') if 'on' in line.lower()]
            results.append({
                'check_type': 'network',
                'name': 'Sharing Services',
                'status': len(active_shares) == 0,
                'details': f"Found {len(active_shares)} active sharing services:\n" + '\n'.join(active_shares)
            })
            print(f"✓ Found {len(active_shares)} active sharing services")

        # Check firewall status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'])
        is_firewall_enabled = success and '1' in stdout
        results.append({
            'check_type': 'network',
            'name': 'Firewall Status',
            'status': is_firewall_enabled,
            'details': 'Firewall is enabled' if is_firewall_enabled else 'Firewall is disabled'
        })
        print(f"✓ Firewall: {'Enabled' if is_firewall_enabled else 'Disabled'}")

        # Check stealth mode status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'stealthenabled'])
        is_stealth_enabled = success and '1' in stdout
        results.append({
            'check_type': 'network',
            'name': 'Stealth Mode Status',
            'status': is_stealth_enabled,
            'details': 'Stealth mode is enabled' if is_stealth_enabled else 'Stealth mode is disabled'
        })
        print(f"✓ Stealth Mode: {'Enabled' if is_stealth_enabled else 'Disabled'}")

        # Check WiFi status
        stdout, success = run_command(['networksetup', '-getairportpower', 'en0'])
        is_wifi_off = success and 'Off' in stdout
        results.append({
            'check_type': 'network',
            'name': 'WiFi Status',
            'status': is_wifi_off,
            'details': 'WiFi is disabled' if is_wifi_off else 'WiFi is enabled'
        })
        print(f"✓ WiFi: {'Disabled' if is_wifi_off else 'Enabled'}")

        # Check Bluetooth status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.Bluetooth', 'ControllerPowerState'])
        is_bluetooth_off = success and '0' in stdout
        results.append({
            'check_type': 'network',
            'name': 'Bluetooth Status',
            'status': is_bluetooth_off,
            'details': 'Bluetooth is disabled' if is_bluetooth_off else 'Bluetooth is enabled'
        })
        print(f"✓ Bluetooth: {'Disabled' if is_bluetooth_off else 'Enabled'}")

        # Check remote login status
        stdout, success = run_command(['systemsetup', '-getremotelogin'])
        is_remote_login_off = success and 'Off' in stdout
        results.append({
            'check_type': 'network',
            'name': 'Remote Login Status',
            'status': is_remote_login_off,
            'details': 'Remote login is disabled' if is_remote_login_off else 'Remote login is enabled'
        })
        print(f"✓ Remote Login: {'Disabled' if is_remote_login_off else 'Enabled'}")

        # Check network time status
        stdout, success = run_command(['systemsetup', '-getnetworktimeserver'])
        is_network_time_on = success and 'On' in stdout
        results.append({
            'check_type': 'network',
            'name': 'Network Time Status',
            'status': is_network_time_on,
            'details': 'Network time is enabled' if is_network_time_on else 'Network time is disabled'
        })
        print(f"✓ Network Time: {'Enabled' if is_network_time_on else 'Disabled'}")

        # Check DNS over HTTPS status
        stdout, success = run_command(['defaults', 'read', '/Library/Preferences/com.apple.dnssd', 'DOHEnabled'])
        is_dns_over_https_enabled = success and '1' in stdout
        results.append({
            'check_type': 'network',
            'name': 'DNS over HTTPS Status',
            'status': is_dns_over_https_enabled,
            'details': 'DNS over HTTPS is enabled' if is_dns_over_https_enabled else 'DNS over HTTPS is disabled'
        })
        print(f"✓ DNS over HTTPS: {'Enabled' if is_dns_over_https_enabled else 'Disabled'}")

        return results

    def check_process_security(self) -> List[Dict]:
        """Monitor processes and launch agents"""
        print("\nChecking Process Security...")
        results = []
        
        def run_command(cmd):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.stdout.strip(), result.returncode == 0
            except Exception as e:
                return str(e), False

        # Check launch agents
        launch_agent_paths = [
            '~/Library/LaunchAgents',
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/System/Library/LaunchAgents',
            '/System/Library/LaunchDaemons'
        ]
        
        all_agents = []
        for path in launch_agent_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                agents = [f for f in os.listdir(expanded_path) if f.endswith('.plist')]
                all_agents.extend([os.path.join(path, agent) for agent in agents])
        
        results.append({
            'check_type': 'process',
            'name': 'Launch Agents',
            'status': True,  # Informational
            'details': f"Found {len(all_agents)} launch agents/daemons:\n" + '\n'.join(all_agents[:5])
        })
        print(f"✓ Found {len(all_agents)} launch agents/daemons")

        # Check for suspicious processes
        stdout, success = run_command(['ps', 'aux'])
        if success:
            processes = stdout.split('\n')[1:]  # Skip header
            high_cpu_processes = [p for p in processes if len(p.split()) > 2 and float(p.split()[2]) > 50]
            results.append({
                'check_type': 'process',
                'name': 'High CPU Processes',
                'status': len(high_cpu_processes) == 0,
                'details': f"Found {len(high_cpu_processes)} processes using >50% CPU:\n" + '\n'.join(high_cpu_processes)
            })
            print(f"✓ Found {len(high_cpu_processes)} high CPU processes")

        return results

    def check_vulnerabilities(self, apps: List[Dict]) -> List[Dict]:
        """Check for known vulnerabilities in installed applications"""
        print("\nChecking for Vulnerabilities...")
        results = []
        
        # Load Fleet's Mac Office vulnerability data
        fleet_vulns = self.load_fleet_vulnerabilities()
        
        # Check each app for vulnerabilities
        for app in apps:
            app_vulns = []
            
            # Check against Fleet data
            if app['name'].lower() in ['microsoft word', 'microsoft excel', 'microsoft powerpoint', 'microsoft outlook']:
                app_vulns.extend(self.check_fleet_vulns(app, fleet_vulns))
            
            # Check Homebrew packages if applicable
            if self.is_homebrew_package(app['name']):
                brew_vulns = self.check_homebrew_vulns(app['name'])
                app_vulns.extend(brew_vulns)
            
            if app_vulns:
                results.append({
                    'app_name': app['name'],
                    'version': app['version'],
                    'vulnerabilities': app_vulns
                })
                print(f"✓ Found {len(app_vulns)} vulnerabilities in {app['name']}")
        
        return results

    def load_fleet_vulnerabilities(self) -> Dict:
        """Load and parse Fleet's Mac Office vulnerability data"""
        # This would normally fetch from Fleet's API or local cache
        # For now, return a sample structure
        return {
            'microsoft_office': {
                '16.73': ['CVE-2023-1234', 'CVE-2023-5678'],
                '16.74': ['CVE-2023-9012']
            }
        }

    def is_homebrew_package(self, name: str) -> bool:
        """Check if an application is installed via Homebrew"""
        try:
            result = subprocess.run(['brew', 'list', '--versions', name], 
                                 capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def check_homebrew_vulns(self, package: str) -> List[Dict]:
        """Check for vulnerabilities in Homebrew packages"""
        vulns = []
        try:
            result = subprocess.run(['brew', 'audit', package], 
                                 capture_output=True, text=True)
            if 'vulnerability' in result.stdout.lower():
                vulns.append({
                    'id': 'BREW-AUDIT',
                    'description': result.stdout,
                    'severity': 'MEDIUM'
                })
        except:
            pass
        return vulns

    def check_fleet_vulns(self, app: Dict, fleet_data: Dict) -> List[Dict]:
        """Check for vulnerabilities using Fleet's data"""
        vulns = []
        app_key = app['name'].lower().replace(' ', '_')
        if app_key in fleet_data:
            for version, cves in fleet_data[app_key].items():
                if self.is_version_vulnerable(app['version'], version):
                    for cve in cves:
                        vulns.append({
                            'id': cve,
                            'description': f'Vulnerable to {cve} in version {version}',
                            'severity': 'HIGH'
                        })
        return vulns

    def is_version_vulnerable(self, current: str, vulnerable: str) -> bool:
        """Compare version numbers to check if current version is vulnerable"""
        try:
            current_parts = [int(x) for x in current.split('.')]
            vulnerable_parts = [int(x) for x in vulnerable.split('.')]
            
            for i in range(max(len(current_parts), len(vulnerable_parts))):
                current_num = current_parts[i] if i < len(current_parts) else 0
                vulnerable_num = vulnerable_parts[i] if i < len(vulnerable_parts) else 0
                
                if current_num < vulnerable_num:
                    return True
                elif current_num > vulnerable_num:
                    return False
            
            return True  # Versions are equal
        except:
            return False

    def calculate_vulnerability_score(self, app: Dict) -> Tuple[float, List[Dict]]:
        """Calculate vulnerability score for an application using NVD data"""
        # This is a simplified version - in production you'd want to use the NVD API
        # and implement proper CPE matching
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": f"{app['name']} {app['version']}",
            "resultsPerPage": 5
        }
        
        vulnerabilities = []
        try:
            response = requests.get(base_url, params=params)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                    if metrics:
                        vulnerabilities.append({
                            'cve_id': cve.get('id'),
                            'cvss_score': metrics.get('cvssData', {}).get('baseScore', 0)
                        })
        except Exception as e:
            print(f"Error fetching vulnerability data: {e}")
        
        avg_score = sum(v['cvss_score'] for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0
        return avg_score, vulnerabilities

    def get_system_info(self) -> Dict:
        """Gather detailed system information including hardware, OS version, and disk space"""
        info = {}
        
        # Get OS version
        stdout, success = self._safe_run_command(['sw_vers'])
        if success:
            for line in stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip()] = value.strip()
        
        # Get hardware info
        stdout, success = self._safe_run_command(['system_profiler', 'SPHardwareDataType'])
        if success:
            for line in stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip()] = value.strip()
        
        # Get disk space information
        stdout, success = self._safe_run_command(['df', '-h'])
        if success:
            disks = []
            lines = stdout.split('\n')[1:]  # Skip header
            for line in lines:
                if line:
                    parts = line.split()
                    if len(parts) >= 6:
                        disk = {
                            'filesystem': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'capacity': parts[4],
                            'mounted_on': parts[5]
                        }
                        disks.append(disk)
            info['disk_space'] = disks
        
        # Get APFS container information for more detailed storage analysis
        stdout, success = self._safe_run_command(['diskutil', 'list', '-plist'])
        if success:
            try:
                disk_list = plistlib.loads(stdout.encode())
                info['storage_details'] = disk_list
            except:
                pass
                
        return info

    def save_results(self, apps: List[Dict], cis_checks: List[Dict], 
                    network_checks: List[Dict], process_checks: List[Dict],
                    vuln_results: List[Dict], system_info: Dict, cis_ram_results: List[Dict]):
        """Save all scan results to JSON files"""
        results_dir = Path('reports')
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Save application inventory
        with open(results_dir / f"application_inventory_{self.today}.json", 'w') as f:
            json.dump(apps, f, indent=4)
        
        # Save CIS checks
        with open(results_dir / f"cis_checks_{self.today}.json", 'w') as f:
            json.dump(cis_checks, f, indent=4)
        
        # Save network checks
        with open(results_dir / f"network_checks_{self.today}.json", 'w') as f:
            json.dump(network_checks, f, indent=4)
        
        # Save process checks
        with open(results_dir / f"process_checks_{self.today}.json", 'w') as f:
            json.dump(process_checks, f, indent=4)
        
        # Save system info
        with open(results_dir / f"system_info_{self.today}.json", 'w') as f:
            json.dump(system_info, f, indent=4)
        
        # Save vulnerabilities
        with open(results_dir / f"vulnerabilities_{self.today}.json", 'w') as f:
            json.dump(vuln_results, f, indent=4)
        
        # Save CIS RAM results
        with open(results_dir / f"cis_ram_results_{self.today}.json", 'w') as f:
            json.dump(cis_ram_results, f, indent=4)

    def generate_report(self, apps: List[Dict], cis_checks: List[Dict], 
                       network_checks: List[Dict], process_checks: List[Dict],
                       vuln_results: List[Dict], system_info: Dict, cis_ram_results: List[Dict]):
        """Generate detailed reports in both text and JSON formats"""
        report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = Path('reports') / f"security_report_{report_time}.txt"
        json_path = Path('reports') / f"security_report_{report_time}.json"
        
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w') as f:
            f.write("=== macOS Security Assessment Report ===\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # System Information
            f.write("=== System Information ===\n")
            if 'ProductName' in system_info:
                f.write(f"OS: {system_info.get('ProductName', 'Unknown')} {system_info.get('ProductVersion', 'Unknown')}\n")
            if 'Model Name' in system_info:
                f.write(f"Model: {system_info.get('Model Name', 'Unknown')}\n")
            if 'Processor Name' in system_info:
                f.write(f"Processor: {system_info.get('Processor Name', 'Unknown')}\n")
            if 'Memory' in system_info:
                f.write(f"Memory: {system_info.get('Memory', 'Unknown')}\n")
            
            # Disk Space Information
            if 'disk_space' in system_info:
                f.write("\n=== Disk Space Information ===\n")
                for disk in system_info['disk_space']:
                    f.write(f"\nFilesystem: {disk['filesystem']}\n")
                    f.write(f"Size: {disk['size']}\n")
                    f.write(f"Used: {disk['used']} ({disk['capacity']})\n")
                    f.write(f"Available: {disk['available']}\n")
                    f.write(f"Mounted on: {disk['mounted_on']}\n")
            
            # CIS Compliance Results
            f.write("\n=== CIS Compliance Results ===\n")
            
            # Group checks by level
            level1_checks = [c for c in cis_checks if not c.get('level') or c.get('level') == 1]
            level2_checks = [c for c in cis_checks if c.get('level') == 2]
            level3_checks = [c for c in cis_checks if c.get('level') == 3]
            
            # Level 1 Results
            f.write("\nLevel 1 (Basic) Checks:\n")
            level1_score = sum(c['score'] for c in level1_checks)
            level1_max = 40
            f.write(f"Score: {(level1_score/level1_max)*100:.1f}%\n")
            for check in level1_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']} ({check['cis_ref']})\n")
                f.write(f"   Risk: {check['risk']}\n")
                f.write(f"   Impact: {check['impact']}\n")
                f.write(f"   Details: {check['details']}\n")
            
            # Level 2 Results
            f.write("\nLevel 2 (Advanced) Checks:\n")
            level2_score = sum(c['score'] for c in level2_checks)
            level2_max = 7
            f.write(f"Score: {(level2_score/level2_max)*100:.1f}%\n")
            for check in level2_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']} ({check['cis_ref']})\n")
                f.write(f"   Risk: {check['risk']}\n")
                f.write(f"   Impact: {check['impact']}\n")
                f.write(f"   Details: {check['details']}\n")
            
            # Level 3 Results
            f.write("\nLevel 3 (Enterprise) Checks:\n")
            level3_score = sum(c['score'] for c in level3_checks)
            level3_max = 11
            f.write(f"Score: {(level3_score/level3_max)*100:.1f}%\n")
            for check in level3_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']} ({check['cis_ref']})\n")
                f.write(f"   Risk: {check['risk']}\n")
                f.write(f"   Impact: {check['impact']}\n")
                f.write(f"   Details: {check['details']}\n")
            
            # Network Security
            f.write("\n=== Network Security ===\n")
            for check in network_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Process Security
            f.write("\n=== Process Security ===\n")
            for check in process_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Vulnerabilities
            f.write("\n=== Vulnerability Assessment ===\n")
            if vuln_results:
                for vuln in vuln_results:
                    f.write(f"\nApplication: {vuln.get('name', 'Unknown')}\n")
                    f.write(f"Version: {vuln.get('version', 'Unknown')}\n")
                    f.write(f"Risk Score: {vuln.get('risk_score', 'N/A')}\n")
                    if 'vulnerabilities' in vuln:
                        f.write("Known Vulnerabilities:\n")
                        for v in vuln['vulnerabilities']:
                            f.write(f"- {v}\n")
            else:
                f.write("No vulnerabilities found\n")
            
            # CIS RAM Results
            if cis_ram_results:
                f.write("\n=== CIS RAM Assessment ===\n")
                for result in cis_ram_results:
                    f.write(f"\nControl {result['id']}: {result['title']}\n")
                    f.write(f"Status: {'Implemented' if result['status'] else 'Not Implemented'}\n")
                    if result.get('description'):
                        f.write(f"Description: {result['description']}\n")
                    if result.get('implementation'):
                        f.write(f"Implementation: {result['implementation']}\n")
            
            # Executive Summary
            f.write("\n=== Executive Summary ===\n")
            total_score = level1_score + level2_score + level3_score
            total_max = 40 + 7 + 11
            overall_percent = (total_score / total_max) * 100
            f.write(f"Overall Security Score: {overall_percent:.1f}%\n")
            f.write(f"CIS Level 1 (Basic) Score: {(level1_score/level1_max)*100:.1f}%\n")
            f.write(f"CIS Level 2 (Advanced) Score: {(level2_score/level2_max)*100:.1f}%\n")
            f.write(f"CIS Level 3 (Enterprise) Score: {(level3_score/level3_max)*100:.1f}%\n")
            
            vuln_count = sum(len(v.get('vulnerabilities', [])) for v in vuln_results)
            f.write(f"Total Vulnerabilities Found: {vuln_count}\n")
            
            # Save as JSON for machine processing
            json_data = {
                'timestamp': datetime.now().isoformat(),
                'system_info': system_info,
                'overall_score': (passed_checks / total_checks) * 100 if total_checks > 0 else 0,
                'total_checks': total_checks,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'risks': {
                    'high': len(high_risks),
                    'medium': len(medium_risks),
                    'low': len(low_risks)
                },
                'sections': self.report_data['sections']
            }
            
            with open(json_path, 'w') as jf:
                json.dump(json_data, jf, indent=2)

    def get_recommendation(self, check_name: str) -> str:
        """Get recommendation for a failed check"""
        recommendations = {
            '1.1 FileVault Encryption': 
                "Enable FileVault encryption via System Settings > Security & Privacy > FileVault",
            '1.2 System Integrity Protection': 
                "Enable SIP by booting into Recovery Mode and running 'csrutil enable'",
            '1.3 Gatekeeper': 
                "Enable Gatekeeper via System Settings > Security & Privacy > Security",
            '2.1 Firewall': 
                "Enable Firewall via System Settings > Security & Privacy > Firewall",
            '2.2 Remote Login (SSH)': 
                "Disable Remote Login via System Settings > Sharing > Remote Login",
            '2.3 Network Time': 
                "Enable network time synchronization via System Settings > Date & Time",
            '3.1 Guest Account': 
                "Disable Guest Account via System Settings > Users & Groups",
            '3.2 Automatic Login': 
                "Disable Automatic Login via System Settings > Users & Groups > Login Options",
            '4.1 Automatic Updates': 
                "Enable automatic updates via System Settings > Software Update",
            '5.1 Analytics Data Collection': 
                "Disable Analytics Data Collection via System Settings > Security & Privacy > Privacy > Analytics"
        }
        return recommendations.get(check_name, "No specific recommendation available")

    def check_dns_history(self) -> Dict:
        """Collect DNS history and configuration data"""
        dns_info = {
            'current_config': {},
            'history': [],
            'resolvers': [],
            'search_domains': []
        }
        
        # Get current DNS configuration (no sudo required)
        dns_config = self._safe_run_command(['scutil', '--dns'])
        if dns_config.returncode == 0:
            dns_info['current_config'] = self._parse_dns_output(dns_config.stdout)

        # Get search domains (no sudo required)
        search_domains = self._safe_run_command(['networksetup', '-getsearchdomains', 'Wi-Fi'])
        if search_domains.returncode == 0:
            dns_info['search_domains'] = search_domains.stdout.strip().split('\n')

        return dns_info

    def _parse_dns_output(self, output: str) -> Dict:
        """Parse DNS configuration output"""
        dns_info = {
            'nameservers': [],
            'search_domains': [],
            'configuration': {}
        }
        
        try:
            # Parse nameservers
            result = subprocess.run(['scutil', '--dns'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                if 'nameserver[' in line:
                    server = line.split()[-1]
                    dns_info['nameservers'].append(server)
                elif 'search domain[' in line:
                    domain = line.split()[-1]
                    dns_info['search_domains'].append(domain)
                    
            # Get DNS configuration
            result = subprocess.run(['networksetup', '-getdnsservers', 'Wi-Fi'], capture_output=True, text=True)
            dns_info['configuration']['wifi'] = result.stdout.strip()
            
            result = subprocess.run(['networksetup', '-getsearchdomains', 'Wi-Fi'], capture_output=True, text=True)
            dns_info['configuration']['search_domains'] = result.stdout.strip()
            
        except Exception as e:
            dns_info['error'] = str(e)
            
        return dns_info

    def _check_cis_level1(self) -> List[Dict]:
        """Basic security configuration checks (CIS Level 1)"""
        checks = []
        
        # Check FileVault
        try:
            filevault = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
            checks.append({
                'title': 'FileVault Encryption',
                'status': 'pass' if 'FileVault is On' in filevault.stdout else 'fail',
                'output': filevault.stdout.strip()
            })
        except Exception as e:
            checks.append({
                'title': 'FileVault Encryption',
                'status': 'error',
                'output': str(e)
            })

        # Check Firewall
        try:
            firewall = subprocess.run(['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'], 
                                   capture_output=True, text=True)
            checks.append({
                'title': 'Firewall Status',
                'status': 'pass' if firewall.stdout.strip() == '1' else 'fail',
                'output': 'Firewall is enabled' if firewall.stdout.strip() == '1' else 'Firewall is disabled'
            })
        except Exception as e:
            checks.append({
                'title': 'Firewall Status',
                'status': 'error',
                'output': str(e)
            })

        # Check Software Updates
        try:
            updates = subprocess.run(['softwareupdate', '--schedule'], capture_output=True, text=True)
            checks.append({
                'title': 'Automatic Updates',
                'status': 'pass' if 'on' in updates.stdout.lower() else 'fail',
                'output': updates.stdout.strip()
            })
        except Exception as e:
            checks.append({
                'title': 'Automatic Updates',
                'status': 'error',
                'output': str(e)
            })

        # Check Screen Lock
        try:
            screen_lock = subprocess.run(['defaults', 'read', 'com.apple.screensaver', 'askForPassword'], 
                                      capture_output=True, text=True)
            checks.append({
                'title': 'Screen Lock',
                'status': 'pass' if screen_lock.stdout.strip() == '1' else 'fail',
                'output': 'Screen lock is enabled' if screen_lock.stdout.strip() == '1' else 'Screen lock is disabled'
            })
        except Exception as e:
            checks.append({
                'title': 'Screen Lock',
                'status': 'error',
                'output': str(e)
            })

        # Check Remote Login
        try:
            remote_login = subprocess.run(['systemsetup', '-getremotelogin'], capture_output=True, text=True)
            checks.append({
                'title': 'Remote Login',
                'status': 'pass' if 'Off' in remote_login.stdout else 'fail',
                'output': remote_login.stdout.strip()
            })
        except Exception as e:
            checks.append({
                'title': 'Remote Login',
                'status': 'error',
                'output': str(e)
            })

        return checks

    def _check_cis_level2(self) -> List[Dict]:
        """Advanced security configuration checks (CIS Level 2)"""
        checks = []
        
        # 1. Advanced System Settings
        print("\n1. Advanced System Settings:")
        
        # 1.1 Bluetooth
        stdout, success = self._safe_run_command(['systemsetup', '-getremoteappleevents'])
        is_bluetooth_disabled = success and 'off' in stdout.lower()
        checks.append({
            'name': '1.1 Bluetooth',
            'level': 2,
            'status': is_bluetooth_disabled,
            'score': 2 if is_bluetooth_disabled else 0,
            'details': 'Bluetooth is disabled' if is_bluetooth_disabled else 'Bluetooth is enabled'
        })
        
        # 1.2 IR Remote Control
        stdout, success = self._safe_run_command(['defaults', 'read', '/Library/Preferences/com.apple.driver.AppleIRController', 'DeviceEnabled'])
        is_ir_disabled = success and '0' in stdout
        checks.append({
            'name': '1.2 IR Remote Control',
            'level': 2,
            'status': is_ir_disabled,
            'score': 1 if is_ir_disabled else 0,
            'details': 'IR remote control is disabled' if is_ir_disabled else 'IR remote control is enabled'
        })
        
        # 2. Advanced Network Settings
        print("\n2. Advanced Network Settings:")
        
        # 2.1 IPv6
        stdout, success = self._safe_run_command(['networksetup', '-listallnetworkservices'])
        if success:
            interfaces = stdout.split('\n')[1:]  # Skip first line
            ipv6_disabled = True
            for interface in interfaces:
                if interface:
                    stdout, success = self._safe_run_command(['networksetup', '-getinfo', interface])
                    if success and 'IPv6: Automatic' in stdout:
                        ipv6_disabled = False
                        break
            
            checks.append({
                'name': '2.1 IPv6',
                'level': 2,
                'status': ipv6_disabled,
                'score': 2 if ipv6_disabled else 0,
                'details': 'IPv6 is disabled on all interfaces' if ipv6_disabled else 'IPv6 is enabled on some interfaces'
            })
        
        # 2.2 NFS Server
        stdout, success = self._safe_run_command(['nfsd', 'status'])
        is_nfs_disabled = not success or 'not running' in stdout
        checks.append({
            'name': '2.2 NFS Server',
            'level': 2,
            'status': is_nfs_disabled,
            'score': 2 if is_nfs_disabled else 0,
            'details': 'NFS server is disabled' if is_nfs_disabled else 'NFS server is running'
        })
        
        return checks

    def _check_cis_level3(self) -> List[Dict]:
        """Enterprise security configuration checks (CIS Level 3)"""
        checks = []
        
        # 1. Enterprise Security Settings
        print("\n1. Enterprise Security Settings:")
        
        # 1.1 Smart Card Authentication
        stdout, success = self._safe_run_command(['security', 'authorizationdb', 'read', 'system.login.console'])
        has_smartcard = success and 'SmartCard' in stdout
        checks.append({
            'name': '1.1 Smart Card Authentication',
            'level': 3,
            'status': has_smartcard,
            'score': 3 if has_smartcard else 0,
            'details': 'Smart card authentication is configured' if has_smartcard else 'Smart card authentication not configured'
        })
        
        # 1.2 MDM Enrollment
        stdout, success = self._safe_run_command(['profiles', 'status', '-type', 'enrollment'])
        is_mdm_enrolled = success and 'Enrolled via DEP' in stdout
        checks.append({
            'name': '1.2 MDM Enrollment',
            'level': 3,
            'status': is_mdm_enrolled,
            'score': 3 if is_mdm_enrolled else 0,
            'details': 'Device is enrolled in MDM' if is_mdm_enrolled else 'Device is not enrolled in MDM'
        })
        
        # 1.3 Security Baseline
        stdout, success = self._safe_run_command(['profiles', '-P'])
        has_security_baseline = success and any('Security' in line for line in stdout.split('\n'))
        checks.append({
            'name': '1.3 Security Baseline Profile',
            'level': 3,
            'status': has_security_baseline,
            'score': 3 if has_security_baseline else 0,
            'details': 'Security baseline profile is installed' if has_security_baseline else 'No security baseline profile found'
        })
        
        # 2. Advanced Logging
        print("\n2. Advanced Logging:")
        
        # 2.1 Remote Logging
        stdout, success = self._safe_run_command(['sudo', 'grep', 'RemoteLogServer', '/etc/syslog.conf'])
        has_remote_logging = success and '@' in stdout
        checks.append({
            'name': '2.1 Remote Logging',
            'level': 3,
            'status': has_remote_logging,
            'score': 2 if has_remote_logging else 0,
            'details': 'Remote logging is configured' if has_remote_logging else 'Remote logging not configured'
        })
        
        return checks

    def check_cis_compliance(self) -> List[Dict]:
        """Perform comprehensive CIS benchmark checks for all levels"""
        all_checks = []
        
        # Level 1 Checks (Basic)
        level1_checks = self._check_cis_level1()
        all_checks.extend(level1_checks)
        
        # Level 2 Checks (Advanced)
        level2_checks = self._check_cis_level2()
        all_checks.extend(level2_checks)
        
        # Level 3 Checks (Enterprise)
        level3_checks = self._check_cis_level3()
        all_checks.extend(level3_checks)
        
        # Calculate total score per level
        level1_score = sum(check['score'] for check in level1_checks)
        level2_score = sum(check['score'] for check in level2_checks)
        level3_score = sum(check['score'] for check in level3_checks)
        
        # Calculate max possible scores
        level1_max = 40  # Sum of all possible level 1 scores
        level2_max = 7   # Sum of all possible level 2 scores
        level3_max = 11  # Sum of all possible level 3 scores
        
        # Calculate percentages
        level1_percent = (level1_score / level1_max) * 100
        level2_percent = (level2_score / level2_max) * 100
        level3_percent = (level3_score / level3_max) * 100
        
        print(f"\nCIS Compliance Scores:")
        print(f"Level 1 (Basic): {level1_percent:.1f}%")
        print(f"Level 2 (Advanced): {level2_percent:.1f}%")
        print(f"Level 3 (Enterprise): {level3_percent:.1f}%")
        
        return all_checks

    def save_report(self, results: Dict, recommendations: List[Dict]):
        """Save scan results and recommendations"""
        # Create reports directory if it doesn't exist
        report_dir = Path('reports')
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = report_dir / f'security_report_{self.today}.md'
        
        with open(report_file, 'w') as f:
            f.write("# Security Scan Report\n\n")
            f.write(self.generate_executive_summary(results))
            
            f.write("\n\n## Detailed Findings\n\n")
            for check in results['checks']:
                f.write(f"### {check['title']}\n")
                f.write(f"Status: {check['status'].upper()}\n")
                f.write(f"Details: {check['output']}\n\n")
            
            if 'dns_info' in results:
                f.write("\n## DNS Configuration\n\n")
                dns_info = results['dns_info']
                
                if 'nameservers' in dns_info['current_config']:
                    f.write("### Nameservers\n")
                    for ns in dns_info['current_config']['nameservers']:
                        f.write(f"- {ns}\n")
                
                if 'recommendations' in dns_info:
                    f.write("\n### DNS Recommendations\n")
                    for rec in dns_info['recommendations']:
                        f.write(f"\n**{rec['issue']}** (Risk: {rec['risk']})\n")
                        f.write(f"- {rec['recommendation']}\n")
            
            f.write("\n## Security Recommendations\n\n")
            for rec in recommendations:
                f.write(f"### {rec['title']} (Risk: {rec['risk']})\n")
                f.write(f"Impact: {rec['impact']}\n\n")
                f.write("Steps to Remediate:\n")
                for step in rec['steps']:
                    f.write(f"1. {step}\n")
                f.write(f"\nVerification: {rec['verification']}\n\n")

    def generate_recommendations(self, check_results: Dict) -> List[Dict]:
        """Generate detailed recommendations for failed checks"""
        recommendations = []
        
        remediation_guides = {
            'firewall': {
                'title': 'Enable and Configure Firewall',
                'risk': 'HIGH',
                'impact': 'System is vulnerable to unauthorized network access and potential malware communication.',
                'steps': [
                    'Open System Settings > Network > Firewall',
                    'Click "Turn On Firewall"',
                    'Click "Firewall Options" to configure application access',
                    'Enable stealth mode to prevent probe responses'
                ],
                'verification': 'Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate'
            },
            'auto_updates': {
                'title': 'Enable Automatic Updates',
                'risk': 'HIGH',
                'impact': 'System may miss critical security patches and vulnerability fixes.',
                'steps': [
                    'Open System Settings > Software Update',
                    'Enable "Automatic Updates"',
                    'Check all options for comprehensive updates'
                ],
                'verification': 'Run: softwareupdate --schedule | grep "Automatic check"'
            },
            'network_time': {
                'title': 'Enable Network Time',
                'risk': 'MEDIUM',
                'impact': 'System logs may have incorrect timestamps, affecting security auditing.',
                'steps': [
                    'Open System Settings > Date & Time',
                    'Click the lock to make changes',
                    'Check "Set date and time automatically"'
                ],
                'verification': 'Run: sudo systemsetup -getusingnetworktime'
            },
            'audit_logging': {
                'title': 'Configure System Auditing',
                'risk': 'HIGH',
                'impact': 'Security events may not be properly tracked and investigated.',
                'steps': [
                    'Enable system auditing:',
                    '1. sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist',
                    '2. sudo defaults write /etc/security/audit_control flags lo,aa,ad,fd,fm,-all',
                    '3. sudo audit -s'
                ],
                'verification': 'Run: sudo praudit -l /var/audit/current'
            }
        }

        # Check Firewall
        if not self._is_firewall_enabled():
            recommendations.append(remediation_guides['firewall'])

        # Check Auto Updates
        if not self._is_autoupdate_enabled():
            recommendations.append(remediation_guides['auto_updates'])

        # Check Network Time
        if not self._is_network_time_enabled():
            recommendations.append(remediation_guides['network_time'])

        # Check Audit Logging
        if not self._is_audit_logging_enabled():
            recommendations.append(remediation_guides['audit_logging'])

        return recommendations

    def _is_firewall_enabled(self) -> bool:
        """Check if firewall is enabled without keychain access"""
        try:
            result = subprocess.run(
                ['defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == '1'
        except Exception:
            return False

    def _is_autoupdate_enabled(self) -> bool:
        """Check if automatic updates are enabled"""
        try:
            result = subprocess.run(
                ['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate.plist', 'AutomaticCheckEnabled'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == '1'
        except Exception:
            return False

    def _is_network_time_enabled(self) -> bool:
        """Check if network time is enabled"""
        try:
            result = subprocess.run(['systemsetup', '-getnetworktimeserver'], capture_output=True, text=True)
            return 'On' in result.stdout
        except Exception:
            return False

    def _is_audit_logging_enabled(self) -> bool:
        """Check if audit logging is enabled"""
        try:
            result = subprocess.run(['auditctl', '-l'], capture_output=True, text=True)
            return len(result.stdout.strip()) > 0
        except Exception:
            return False

    def generate_executive_summary(self, results: Dict) -> str:
        """Generate an executive summary of the security scan"""
        summary = []
        total_checks = len(results['checks'])
        passed_checks = len([c for c in results['checks'] if c['status'] == 'pass'])
        
        risk_score = (passed_checks / total_checks) * 100
        
        summary.append("\n=== Executive Summary ===\n")
        summary.append(f"Security Risk Score: {risk_score:.1f}%")
        summary.append(f"Total Checks: {total_checks}")
        summary.append(f"Passed: {passed_checks}")
        summary.append(f"Failed: {total_checks - passed_checks}")
        
        if total_checks - passed_checks > 0:
            summary.append("\nCritical Issues:")
            for check in results['checks']:
                if check['status'] == 'fail':
                    summary.append(f"- {check['title']}")
        
        recommendations = self.generate_recommendations(results)
        if recommendations:
            summary.append("\nTop Recommendations:")
            for rec in recommendations:
                summary.append(f"\n{rec['title']} (Risk: {rec['risk']})")
                summary.append(f"Impact: {rec['impact']}")
                summary.append("Remediation Steps:")
                for step in rec['steps']:
                    summary.append(f"  - {step}")
        
        return "\n".join(summary)

    def run_scan(self):
        """Run the security scan"""
        print("\nStarting macOS security scan...\n")
        print("=== Security Scanner Information ===")
        print("This scanner will check your system security settings and may require:")
        print("1. Administrator (sudo) privileges for some checks")
        print("2. Keychain access for certificate and security checks\n")
        
        print("The following checks will be performed:")
        print("- System configuration")
        print("- Security settings")
        print("- DNS configuration")
        print("- Certificate validation")
        print("- CIS compliance checks\n")
        
        try:
            print("\nRunning Basic Security Checks...")
            
            print("\n1. Checking System Configuration...")
            # System Security
            system_results = self._check_system_security()
            self.report_data['sections']['system_security'] = system_results
            
            print("\n2. Checking Password Policy...")
            # Password Policy
            password_results = self._check_password_policy()
            self.report_data['sections']['password_policy'] = password_results
            
            print("\n3. Checking Screen Saver Settings...")
            # Screen Saver
            screen_results = self._check_screen_saver()
            self.report_data['sections']['screen_saver'] = screen_results
            
            print("\n4. Checking Network Security...")
            # Network Security
            network_results = self._check_network_security()
            self.report_data['sections']['network_security'] = network_results
            
            print("\n5. Checking Sharing Settings...")
            # Sharing Settings
            sharing_results = self._check_sharing_settings()
            self.report_data['sections']['sharing_settings'] = sharing_results
            
            print("\n6. Checking Software Updates...")
            # Software Updates
            updates_results = self._check_software_updates()
            self.report_data['sections']['software_updates'] = updates_results
            
            print("\n7. Checking Logging and Auditing...")
            # Logging and Auditing
            logging_results = self._check_logging_auditing()
            self.report_data['sections']['logging_auditing'] = logging_results
            
            print("\n8. Generating Security Recommendations...")
            self.generate_report()
            
            print("\n9. Security Assessment Complete!")
            
        except Exception as e:
            print(f"\nError during scan: {str(e)}")
            import traceback
            traceback.print_exc()
            
    def check_cis_level1(self) -> Dict:
        """Perform CIS Level 1 compliance checks"""
        results = {
            'checks': [],
            'score': 0.0,
            'total_checks': 0,
            'passed_checks': 0
        }
        
        # 1. System Security
        self._check_system_security(results)
        
        # 2. Password Policy
        self._check_password_policy(results)
        
        # 3. Screen Saver Settings
        self._check_screen_saver(results)
        
        # 4. Network Security
        self._check_network_security(results)
        
        # 5. Sharing Settings
        self._check_sharing_settings(results)
        
        # 6. Software Updates
        self._check_software_updates(results)
        
        # 7. Logging and Auditing
        self._check_logging_auditing(results)
        
        # Calculate score
        if results['total_checks'] > 0:
            results['score'] = (results['passed_checks'] / results['total_checks']) * 100
            
        return results
        
    def check_cis_level2(self) -> Dict:
        """Perform CIS Level 2 compliance checks"""
        results = {
            'checks': [],
            'score': 0.0,
            'total_checks': 0,
            'passed_checks': 0
        }
        
        # 1. Bluetooth Security
        self._check_bluetooth_security(results)
        
        # 2. IR Remote Control
        self._check_ir_remote(results)
        
        # 3. IPv6 Configuration
        self._check_ipv6_config(results)
        
        # 4. NFS Server Status
        self._check_nfs_server(results)
        
        # Calculate score
        if results['total_checks'] > 0:
            results['score'] = (results['passed_checks'] / results['total_checks']) * 100
            
        return results
        
    def check_cis_level3(self) -> Dict:
        """Perform CIS Level 3 compliance checks"""
        results = {
            'checks': [],
            'score': 0.0,
            'total_checks': 0,
            'passed_checks': 0
        }
        
        # 1. Smart Card Authentication
        self._check_smart_card_auth(results)
        
        # 2. MDM Enrollment
        self._check_mdm_enrollment(results)
        
        # 3. Security Baseline Profiles
        self._check_security_profiles(results)
        
        # 4. Remote Logging
        self._check_remote_logging(results)
        
        # Calculate score
        if results['total_checks'] > 0:
            results['score'] = (results['passed_checks'] / results['total_checks']) * 100
            
        return results
        
    def assess_cis_ram_controls(self) -> Dict:
        """Perform CIS RAM control assessment"""
        results = {
            'controls': {},
            'overall_score': 0.0,
            'control_scores': {},
            'recommendations': []
        }
        
        # Get list of controls from workbook
        controls = self.cis_ram_questionnaire.questions.keys()
        
        # Assess each control
        for control_id in controls:
            print(f"\nAssessing CIS RAM Control {control_id}")
            
            # Ask questions for this control
            responses = self.cis_ram_questionnaire.ask_questions(control_id)
            
            # Calculate control score
            score = self.cis_ram_questionnaire.get_control_maturity_score(control_id)
            
            results['controls'][control_id] = {
                'responses': responses,
                'score': score
            }
            
            results['control_scores'][control_id] = score
            
            # Add recommendations if score is low
            if score < 0.6:
                results['recommendations'].append({
                    'control_id': control_id,
                    'current_score': score,
                    'recommendation': f"Improve maturity of control {control_id}. Current score: {score:.2f}"
                })
        
        # Calculate overall score
        if results['control_scores']:
            results['overall_score'] = sum(results['control_scores'].values()) / len(results['control_scores'])
        
        return results
        
    def generate_report(self):
        """Generate comprehensive security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = Path('reports') / f'reports/security_report_{timestamp}.txt'
        json_path = Path('reports') / f'reports/security_report_{timestamp}.json'
        
        # Create reports directory if it doesn't exist
        report_path.parent.mkdir(exist_ok=True)
        
        # Calculate overall statistics
        sections = [s for s in self.report_data['sections'].values() if s is not None]
        total_checks = sum(section['total_checks'] for section in sections)
        passed_checks = sum(section['passed_checks'] for section in sections)
        failed_checks = total_checks - passed_checks if total_checks > 0 else 0
        
        # Categorize risks
        high_risks = []
        medium_risks = []
        low_risks = []
        
        for section in sections:
            for check in section['checks']:
                if check.get('status', '') == 'fail':
                    if check.get('risk', '') == 'HIGH':
                        high_risks.append(check)
                    elif check.get('risk', '') == 'MEDIUM':
                        medium_risks.append(check)
                    else:
                        low_risks.append(check)
        
        with open(report_path, 'w') as f:
            f.write("macOS Security Assessment Report\n")
            f.write("=============================\n\n")
            
            f.write("Executive Summary\n")
            f.write("=================\n")
            if total_checks > 0:
                score = (passed_checks / total_checks) * 100
                f.write(f"Overall Security Score: {score:.1f}%\n")
            f.write(f"Total Checks: {total_checks}\n")
            f.write(f"Passed: {passed_checks}\n")
            f.write(f"Failed: {failed_checks}\n\n")
            
            f.write("Risk Summary\n")
            f.write("============\n")
            f.write(f"High Risk Issues: {len(high_risks)}\n")
            f.write(f"Medium Risk Issues: {len(medium_risks)}\n")
            f.write(f"Low Risk Issues: {len(low_risks)}\n\n")
            
            f.write("Detailed Findings\n")
            f.write("=================\n\n")
            
            for section_name, section_data in self.report_data['sections'].items():
                if section_data is None or not section_data['checks']:
                    continue
                
                # Convert section name from snake_case to Title Case
                section_title = ' '.join(word.capitalize() for word in section_name.split('_'))
                f.write(f"{section_title}\n")
                f.write("-" * len(section_title) + "\n")
                
                for check in section_data['checks']:
                    f.write(f"\n{check.get('title', 'Unnamed Check')}\n")
                    f.write(f"Status: {check.get('status', 'UNKNOWN').upper()}\n")
                    f.write(f"Details: {check.get('details', 'No details available')}\n")
                    if 'risk' in check:
                        f.write(f"Risk Level: {check['risk']}\n")
                    if 'cis_ref' in check:
                        f.write(f"CIS Reference: {check['cis_ref']}\n")
                    if 'impact' in check:
                        f.write(f"Security Impact: {check['impact']}\n")
                    f.write("\n")
                
                f.write("\n")
            
            f.write("\nRecommendations\n")
            f.write("===============\n")
            if high_risks:
                f.write("\nHigh Priority:\n")
                for risk in high_risks:
                    f.write(f"- {risk.get('title', 'Unnamed Check')}: {risk.get('details', 'No details available')}\n")
            
            if medium_risks:
                f.write("\nMedium Priority:\n")
                for risk in medium_risks:
                    f.write(f"- {risk.get('title', 'Unnamed Check')}: {risk.get('details', 'No details available')}\n")
            
            if low_risks:
                f.write("\nLow Priority:\n")
                for risk in low_risks:
                    f.write(f"- {risk.get('title', 'Unnamed Check')}: {risk.get('details', 'No details available')}\n")
        
        # Save raw data as JSON
        json_data = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': (passed_checks / total_checks) * 100 if total_checks > 0 else 0,
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'risks': {
                'high': len(high_risks),
                'medium': len(medium_risks),
                'low': len(low_risks)
            },
            'sections': self.report_data['sections']
        }
        
        with open(json_path, 'w') as f:
            json.dump(json_data, f, indent=2)
            
        print(f"\nDetailed report saved to: {report_path}")
        print(f"JSON data saved to: {json_path}")

    def _check_software_updates(self) -> Dict:
        """Check software update settings"""
        results = {
            'total_checks': 2,
            'passed_checks': 0,
            'checks': []
        }
        
        # Check Auto Update Status using softwareupdate command
        auto_update = self._safe_run_command(['softwareupdate', '--schedule'])
        auto_update_enabled = 'on' in auto_update.lower()
        results['checks'].append({
            'title': 'Automatic Updates Check',
            'status': 'pass' if auto_update_enabled else 'fail',
            'details': f"Automatic update check is {'enabled' if auto_update_enabled else 'disabled'}",
            'expected': 'enabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 1.1',
            'impact': 'System may miss critical security updates'
        })
        if auto_update_enabled:
            results['passed_checks'] += 1
        
        # Check System Update Status
        update_status = self._safe_run_command(['softwareupdate', '-l'])
        no_updates_needed = 'No new software available' in update_status
        results['checks'].append({
            'title': 'System Updates Status',
            'status': 'pass' if no_updates_needed else 'fail',
            'details': f"System {'is up to date' if no_updates_needed else 'has pending updates'}",
            'expected': 'up to date',
            'risk': 'MEDIUM',
            'cis_ref': 'CIS 1.2',
            'impact': 'System may be vulnerable to known security issues'
        })
        if no_updates_needed:
            results['passed_checks'] += 1
        
        return results

    def _check_logging_auditing(self) -> Dict:
        """Check logging and auditing settings"""
        results = {
            'total_checks': 2,
            'passed_checks': 0,
            'checks': []
        }
        
        # Check System Logging
        log_status = self._safe_run_command(['log', 'show', '--last', '1m'])
        has_logs = len(log_status) > 0
        results['checks'].append({
            'title': 'System Logging',
            'status': 'pass' if has_logs else 'fail',
            'details': f"System logging is {'active' if has_logs else 'inactive'}",
            'expected': 'active',
            'risk': 'HIGH',
            'cis_ref': 'CIS 8.1',
            'impact': 'System may not record security-relevant events'
        })
        if has_logs:
            results['passed_checks'] += 1
        
        # Check Log Retention
        log_retention = self._safe_run_command(['log', 'show', '--last', '7d'])
        has_retention = len(log_retention) > 0
        results['checks'].append({
            'title': 'Log Retention',
            'status': 'pass' if has_retention else 'fail',
            'details': f"Log retention is {'properly configured' if has_retention else 'not properly configured'}",
            'expected': 'configured',
            'risk': 'MEDIUM',
            'cis_ref': 'CIS 8.2',
            'impact': 'Historical security events may not be available for analysis'
        })
        if has_retention:
            results['passed_checks'] += 1
        
        return results
    
    def _get_os_version(self) -> str:
        """Get macOS version"""
        try:
            result = self._safe_run_command(['sw_vers', '-productVersion'])
            return result.strip()
        except:
            return 'Unknown'
    
    def _get_build_version(self) -> str:
        """Get macOS build version"""
        try:
            result = self._safe_run_command(['sw_vers', '-buildVersion'])
            return result.strip()
        except:
            return 'Unknown'
    
    def _check_logging_auditing(self) -> Dict:
        """Check logging and auditing settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 8.1 Audit Service
            {
                'id': '8.1.1',
                'title': 'Audit Service Status',
                'command': ['sudo', 'launchctl', 'list', 'com.apple.auditd'],
                'expected': '"PID"',
                'risk': 'HIGH',
                'cis_ref': 'CIS 8.1.1',
                'impact': 'System activities not being logged'
            },
            # 8.2 Audit Files
            {
                'id': '8.2.1',
                'title': 'Audit Files Permissions',
                'command': ['sudo', 'ls', '-l', '/var/audit'],
                'expected': 'dr-x------',
                'risk': 'HIGH',
                'cis_ref': 'CIS 8.2.1',
                'impact': 'Audit logs may be tampered with'
            },
            # 8.3 Audit Configuration
            {
                'id': '8.3.1',
                'title': 'Audit Control Settings',
                'command': ['sudo', 'cat', '/etc/security/audit_control'],
                'expected': 'flags:lo,aa,ad,fd,fm,-all',
                'risk': 'HIGH',
                'cis_ref': 'CIS 8.3.1',
                'impact': 'Important events may not be logged'
            },
            # 8.4 Audit Retention
            {
                'id': '8.4.1',
                'title': 'Audit Log Retention',
                'command': ['sudo', 'cat', '/etc/security/audit_control'],
                'expected': 'expire-after:60d',
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 8.4.1',
                'impact': 'Audit logs may be lost'
            },
            # 8.5 Security Logging
            {
                'id': '8.5.1',
                'title': 'Security Logging Status',
                'command': ['log', 'show', '--predicate', '"subsystem == \"com.apple.security\"" --last 1m'],
                'expected': lambda x: len(x.strip()) > 0,
                'risk': 'HIGH',
                'cis_ref': 'CIS 8.5.1',
                'impact': 'Security events not being logged'
            },
            # 8.6 Log Rotation
            {
                'id': '8.6.1',
                'title': 'System Log Rotation',
                'command': ['sudo', 'cat', '/etc/newsyslog.conf'],
                'expected': '/var/log',
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 8.6.1',
                'impact': 'Logs may fill disk space'
            },
            # 8.7 Log Permissions
            {
                'id': '8.7.1',
                'title': 'System Log Permissions',
                'command': ['sudo', 'ls', '-l', '/var/log/system.log'],
                'expected': '-rw-r-----',
                'risk': 'HIGH',
                'cis_ref': 'CIS 8.7.1',
                'impact': 'Logs may be accessed by unauthorized users'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                if callable(check.get('expected')):
                    passed = check['expected'](result)
                else:
                    passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results

    def _check_password_policy(self) -> Dict:
        """Check password policy settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 5.1 Password Requirements
            {
                'id': '5.1.1',
                'title': 'Password Length Requirement',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'minChars=12',
                'risk': 'HIGH',
                'cis_ref': 'CIS 5.1.1',
                'impact': 'Weak passwords may be used'
            },
            {
                'id': '5.1.2',
                'title': 'Password Complexity',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'requiresAlpha=1',
                'risk': 'HIGH',
                'cis_ref': 'CIS 5.1.2',
                'impact': 'Simple passwords may be used'
            },
            {
                'id': '5.1.3',
                'title': 'Password Special Characters',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'requiresSymbol=1',
                'risk': 'HIGH',
                'cis_ref': 'CIS 5.1.3',
                'impact': 'Passwords may lack special characters'
            },
            # 5.2 Password Age
            {
                'id': '5.2.1',
                'title': 'Maximum Password Age',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'maxMinutesUntilChangePassword=129600',  # 90 days
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 5.2.1',
                'impact': 'Passwords may be used indefinitely'
            },
            {
                'id': '5.2.2',
                'title': 'Minimum Password Age',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'minMinutesUntilChangePassword=1440',  # 24 hours
                'risk': 'LOW',
                'cis_ref': 'CIS 5.2.2',
                'impact': 'Passwords may be changed too frequently'
            },
            # 5.3 Password History
            {
                'id': '5.3.1',
                'title': 'Password History',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'usingHistory=15',
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 5.3.1',
                'impact': 'Old passwords may be reused'
            },
            # 5.4 Account Lockout
            {
                'id': '5.4.1',
                'title': 'Account Lockout Threshold',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'maxFailedLoginAttempts=5',
                'risk': 'HIGH',
                'cis_ref': 'CIS 5.4.1',
                'impact': 'Accounts vulnerable to brute force attacks'
            },
            {
                'id': '5.4.2',
                'title': 'Account Lockout Duration',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'minutesUntilFailedLoginReset=15',
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 5.4.2',
                'impact': 'Locked accounts may be unlocked too quickly'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results

    def _check_screen_saver(self) -> Dict:
        """Check screen saver security settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 6.1 Screen Saver Activation
            {
                'id': '6.1.1',
                'title': 'Screen Saver Activation',
                'command': ['defaults', '-currentHost', 'read', 'com.apple.screensaver', 'idleTime'],
                'expected': lambda x: int(x) <= 1200,  # 20 minutes or less
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 6.1.1',
                'impact': 'System may remain unlocked when unattended'
            },
            # 6.2 Screen Saver Password Protection
            {
                'id': '6.2.1',
                'title': 'Screen Saver Password Protection',
                'command': ['defaults', 'read', 'com.apple.screensaver', 'askForPassword'],
                'expected': '1',
                'risk': 'HIGH',
                'cis_ref': 'CIS 6.2.1',
                'impact': 'Unauthorized access when system is unattended'
            },
            # 6.3 Password Delay
            {
                'id': '6.3.1',
                'title': 'Password Delay After Screen Saver',
                'command': ['defaults', 'read', 'com.apple.screensaver', 'askForPasswordDelay'],
                'expected': '0',
                'risk': 'HIGH',
                'cis_ref': 'CIS 6.3.1',
                'impact': 'Delayed password prompt allows unauthorized access'
            },
            # 6.4 Hot Corners
            {
                'id': '6.4.1',
                'title': 'Hot Corners Configuration',
                'command': ['defaults', 'read', 'com.apple.dock', 'wvous-bl-corner'],
                'expected': '6',  # Screen Saver
                'risk': 'LOW',
                'cis_ref': 'CIS 6.4.1',
                'impact': 'No quick way to activate screen saver'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                if callable(check.get('expected')):
                    try:
                        value = int(result.strip())
                        passed = check['expected'](value)
                    except (ValueError, TypeError):
                        passed = False
                else:
                    passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results

    def _check_system_security(self) -> Dict:
        """Check system security settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 2.1 System Integrity Protection
            {
                'id': '2.1.1',
                'title': 'System Integrity Protection Status',
                'command': ['csrutil', 'status'],
                'expected': 'enabled',
                'risk': 'HIGH',
                'cis_ref': 'CIS 2.1.1',
                'impact': 'System files and processes may be modified by malware'
            },
            # 2.2 FileVault
            {
                'id': '2.2.1',
                'title': 'FileVault Status',
                'command': ['fdesetup', 'status'],
                'expected': 'On',
                'risk': 'HIGH',
                'cis_ref': 'CIS 2.2.1',
                'impact': 'Data may be accessible if device is lost or stolen'
            },
            # 2.3 Gatekeeper
            {
                'id': '2.3.1',
                'title': 'Gatekeeper Status',
                'command': ['spctl', '--status'],
                'expected': 'assessments enabled',
                'risk': 'HIGH',
                'cis_ref': 'CIS 2.3.1',
                'impact': 'Unsigned applications may be executed'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                if callable(check.get('expected')):
                    try:
                        value = int(result.strip())
                        passed = check['expected'](value)
                    except (ValueError, TypeError):
                        passed = False
                else:
                    passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results
    
    def _check_password_policy(self) -> Dict:
        """Check password policy settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 5.1 Password Requirements
            {
                'id': '5.1.1',
                'title': 'Password Length Requirement',
                'command': ['pwpolicy', '-getaccountpolicies'],
                'expected': 'minChars=12',
                'risk': 'HIGH',
                'cis_ref': 'CIS 5.1.1',
                'impact': 'Weak passwords may be used'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results
    
    def _check_screen_saver(self) -> Dict:
        """Check screen saver security settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 6.1 Screen Saver Activation
            {
                'id': '6.1.1',
                'title': 'Screen Saver Activation',
                'command': ['defaults', '-currentHost', 'read', 'com.apple.screensaver', 'idleTime'],
                'expected': lambda x: int(x) <= 1200,  # 20 minutes or less
                'risk': 'MEDIUM',
                'cis_ref': 'CIS 6.1.1',
                'impact': 'System may remain unlocked when unattended'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                if callable(check.get('expected')):
                    try:
                        value = int(result.strip())
                        passed = check['expected'](value)
                    except (ValueError, TypeError):
                        passed = False
                else:
                    passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results

    def _check_network_security(self) -> Dict:
        """Check network security settings"""
        results = {
            'checks': [],
            'total_checks': 0,
            'passed_checks': 0
        }
        
        checks = [
            # 3.1 Firewall
            {
                'id': '3.1.1',
                'title': 'Firewall Status',
                'command': ['sudo', '/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
                'expected': 'enabled',
                'risk': 'HIGH',
                'cis_ref': 'CIS 3.1.1',
                'impact': 'System may be vulnerable to unauthorized network access and potential malware communication.'
            },
            # 3.2 Remote Login
            {
                'id': '3.2.1',
                'title': 'Remote Login Status',
                'command': ['sudo', 'systemsetup', '-getremotelogin'],
                'expected': 'Remote Login: Off',
                'risk': 'HIGH',
                'cis_ref': 'CIS 3.2.1',
                'impact': 'Unauthorized remote access may be possible'
            },
            # 3.3 Remote Management
            {
                'id': '3.3.1',
                'title': 'Remote Management Status',
                'command': ['sudo', 'systemsetup', '-getremotemanagement'],
                'expected': 'Remote Management: Off',
                'risk': 'HIGH',
                'cis_ref': 'CIS 3.3.1',
                'impact': 'Unauthorized remote management may be possible'
            }
        ]
        
        for check in checks:
            try:
                result = self._safe_run_command(check['command'])
                if callable(check.get('expected')):
                    try:
                        value = int(result.strip())
                        passed = check['expected'](value)
                    except (ValueError, TypeError):
                        passed = False
                else:
                    passed = check['expected'] in result
                
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'pass' if passed else 'fail',
                    'details': result.strip() if result.strip() else 'No output',
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
                if passed:
                    results['passed_checks'] += 1
            except Exception as e:
                results['checks'].append({
                    'id': check['id'],
                    'title': check['title'],
                    'status': 'error',
                    'details': str(e),
                    'risk': check['risk'],
                    'cis_ref': check['cis_ref'],
                    'impact': check['impact']
                })
                results['total_checks'] += 1
        
        return results
    
    def _check_sharing_settings(self) -> Dict:
        """Check sharing settings"""
        results = {
            'total_checks': 3,
            'passed_checks': 0,
            'checks': []
        }
        
        # Check File Sharing
        file_sharing = self._safe_run_command(['systemsetup', '-getremoteappleevents'])
        file_sharing_disabled = 'off' in file_sharing.lower()
        results['checks'].append({
            'title': 'File Sharing',
            'status': 'pass' if file_sharing_disabled else 'fail',
            'details': f"File sharing is {'disabled' if file_sharing_disabled else 'enabled'}",
            'expected': 'disabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 2.4.1',
            'impact': 'System may be vulnerable to unauthorized file access'
        })
        if file_sharing_disabled:
            results['passed_checks'] += 1
        
        # Check Remote Management
        remote_mgmt = self._safe_run_command(['systemsetup', '-getremotelogin'])
        remote_mgmt_disabled = 'off' in remote_mgmt.lower()
        results['checks'].append({
            'title': 'Remote Management',
            'status': 'pass' if remote_mgmt_disabled else 'fail',
            'details': f"Remote management is {'disabled' if remote_mgmt_disabled else 'enabled'}",
            'expected': 'disabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 2.4.2',
            'impact': 'Unauthorized remote management may be possible'
        })
        if remote_mgmt_disabled:
            results['passed_checks'] += 1
        
        # Check Screen Sharing
        screen_sharing = self._safe_run_command(['systemsetup', '-getremotelogin'])
        screen_sharing_disabled = 'off' in screen_sharing.lower()
        results['checks'].append({
            'title': 'Screen Sharing',
            'status': 'pass' if screen_sharing_disabled else 'fail',
            'details': f"Screen sharing is {'disabled' if screen_sharing_disabled else 'enabled'}",
            'expected': 'disabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 2.4.3',
            'impact': 'System may be vulnerable to unauthorized screen access'
        })
        if screen_sharing_disabled:
            results['passed_checks'] += 1
        
        return results
    
    def _check_software_updates(self) -> Dict:
        """Check software update settings"""
        results = {
            'total_checks': 2,
            'passed_checks': 0,
            'checks': []
        }
        
        # Check Auto Update Status
        auto_update = self._safe_run_command(['softwareupdate', '--schedule'])
        auto_update_enabled = 'on' in auto_update.lower()
        results['checks'].append({
            'title': 'Automatic Updates Check',
            'status': 'pass' if auto_update_enabled else 'fail',
            'details': f"Automatic update check is {'enabled' if auto_update_enabled else 'disabled'}",
            'expected': 'enabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 1.1',
            'impact': 'System may miss critical security updates'
        })
        if auto_update_enabled:
            results['passed_checks'] += 1
        
        # Check Auto Download Status
        auto_download = self._safe_run_command(['defaults', 'read', '/Library/Preferences/com.apple.commerce', 'AutoUpdate'])
        auto_download_enabled = '1' in auto_download
        results['checks'].append({
            'title': 'Automatic Updates Download',
            'status': 'pass' if auto_download_enabled else 'fail',
            'details': f"Automatic update download is {'enabled' if auto_download_enabled else 'disabled'}",
            'expected': 'enabled',
            'risk': 'MEDIUM',
            'cis_ref': 'CIS 1.2',
            'impact': 'System may delay installation of critical security updates'
        })
        if auto_download_enabled:
            results['passed_checks'] += 1
        
        return results
    
    def _check_logging_auditing(self) -> Dict:
        """Check logging and auditing settings"""
        results = {
            'total_checks': 2,
            'passed_checks': 0,
            'checks': []
        }
        
        # Check Security Auditing Status
        audit_status = self._safe_run_command(['sudo', 'praudit', '-l', '/var/audit/current'])
        audit_enabled = len(audit_status) > 0
        results['checks'].append({
            'title': 'Security Auditing',
            'status': 'pass' if audit_enabled else 'fail',
            'details': f"Security auditing is {'enabled' if audit_enabled else 'disabled'}",
            'expected': 'enabled',
            'risk': 'HIGH',
            'cis_ref': 'CIS 8.1',
            'impact': 'System may not record security-relevant events'
        })
        if audit_enabled:
            results['passed_checks'] += 1
        
        # Check System Log Size
        log_config = self._safe_run_command(['log', 'config'])
        has_logs = 'mode = "simple"' in log_config
        results['checks'].append({
            'title': 'System Logging',
            'status': 'pass' if has_logs else 'fail',
            'details': f"System logging is {'active' if has_logs else 'inactive'}",
            'expected': 'active',
            'risk': 'MEDIUM',
            'cis_ref': 'CIS 8.2',
            'impact': 'System may not maintain adequate logs for security analysis'
        })
        if has_logs:
            results['passed_checks'] += 1
        
        return results

def main():
    """Main execution flow"""
    try:
        scanner = MacDeviceScanner()
        scanner.check_prerequisites()
        
        print("\nRunning Security Checks...\n")
        
        # 1. System Security
        print("1. Checking System Security...")
        system_results = scanner._check_system_security()
        scanner.report_data['sections']['system_security'] = system_results
        
        # 2. Password Policy
        print("2. Checking Password Policy...")
        password_results = scanner._check_password_policy()
        scanner.report_data['sections']['password_policy'] = password_results
        
        # 3. Screen Saver
        print("3. Checking Screen Saver Settings...")
        screen_results = scanner._check_screen_saver()
        scanner.report_data['sections']['screen_saver'] = screen_results
        
        # 4. Network Security
        print("4. Checking Network Security...")
        network_results = scanner._check_network_security()
        scanner.report_data['sections']['network_security'] = network_results
        
        # 5. Sharing Settings
        print("5. Checking Sharing Settings...")
        sharing_results = scanner._check_sharing_settings()
        scanner.report_data['sections']['sharing_settings'] = sharing_results
        
        # 6. Software Updates
        print("6. Checking Software Updates...")
        updates_results = scanner._check_software_updates()
        scanner.report_data['sections']['software_updates'] = updates_results
        
        # 7. Logging and Auditing
        print("7. Checking Logging and Auditing...")
        logging_results = scanner._check_logging_auditing()
        scanner.report_data['sections']['logging_auditing'] = logging_results
        
        print("\n8. Generating Security Recommendations...")
        scanner.generate_report()
        
        print("\n9. Security Assessment Complete!")
        
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
        import traceback
        traceback.print_exc()
        
if __name__ == '__main__':
    main()