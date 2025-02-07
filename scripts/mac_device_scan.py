#!/usr/bin/env python3

import subprocess
import json
import os
import sqlite3
import requests
from datetime import datetime
from pathlib import Path
import plistlib
import re
import csv
from typing import Dict, List, Tuple, Optional
import openpyxl
import logging
import sys

class CISRAMChecker:
    def __init__(self, questions_file: str):
        """Initialize CIS RAM checker with questions file path"""
        self.questions_file = questions_file
        self.questions = self.load_questions()
        self.responses = {}
        
    def load_questions(self) -> Dict:
        """Load questions from JSON file"""
        try:
            with open(self.questions_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading CIS RAM questions: {e}")
            return {"controls": {}}
            
    def assess_controls(self) -> Dict:
        """Assess CIS RAM controls and return results"""
        results = {
            'controls': {},
            'scores': {
                'level1': 0.0,
                'level2': 0.0,
                'overall': 0.0
            },
            'recommendations': []
        }
        
        level1_count = 0
        level2_count = 0
        
        for control_id, control in self.questions['controls'].items():
            control_score = 0
            questions_count = len(control['questions'])
            
            for question in control['questions']:
                # For now, we'll auto-assess based on our security checks
                # In future, this could be a web form or interactive questionnaire
                is_compliant = self._auto_assess_question(question['id'])
                if is_compliant:
                    control_score += 1
                    
                # Track scores by level
                if question['level'] == '1':
                    level1_count += 1
                    if is_compliant:
                        results['scores']['level1'] += 1
                elif question['level'] == '2':
                    level2_count += 1
                    if is_compliant:
                        results['scores']['level2'] += 1
            
            # Calculate control score
            control_score = (control_score / questions_count) * 100 if questions_count > 0 else 0
            results['controls'][control_id] = {
                'title': control['title'],
                'score': control_score,
                'compliant': control_score >= 70  # Consider 70% as passing threshold
            }
            
            # Add recommendations for low-scoring controls
            if control_score < 70:
                results['recommendations'].append({
                    'control_id': control_id,
                    'title': control['title'],
                    'score': control_score,
                    'recommendation': f"Improve compliance with {control['title']} controls. Current score: {control_score:.1f}%"
                })
        
        # Calculate final scores
        if level1_count > 0:
            results['scores']['level1'] = (results['scores']['level1'] / level1_count) * 100
        if level2_count > 0:
            results['scores']['level2'] = (results['scores']['level2'] / level2_count) * 100
            
        total_controls = level1_count + level2_count
        if total_controls > 0:
            results['scores']['overall'] = ((results['scores']['level1'] * level1_count) + 
                                         (results['scores']['level2'] * level2_count)) / total_controls
        
        return results
    
    def _auto_assess_question(self, question_id: str) -> bool:
        """Auto-assess a question based on security checks"""
        # This is where we map questions to actual security checks
        # For now, return a default value
        return True

class CISRAMQuestionnaire:
    def __init__(self, workbook_path: str):
        """Initialize CIS RAM questionnaire with workbook path"""
        self.workbook = openpyxl.load_workbook(workbook_path, data_only=True)
        self.questions = self.load_questions()
        self.responses = {}
        
    def load_questions(self) -> Dict[str, List[Dict]]:
        """Load questions from CIS RAM workbook"""
        questions = {}
        
        try:
            sheet = self.workbook['3 Risk Register Controls v8']
            current_control = None
            current_questions = []
            
            for row in sheet.iter_rows(min_row=2):
                values = [str(cell.value).strip() if cell.value else '' for cell in row[:6]]
                
                # Skip empty rows
                if not any(values):
                    continue
                
                control_id = values[1]
                if control_id and '.' in control_id:  # This is a control ID (e.g., "1.1")
                    if current_control:
                        questions[current_control] = current_questions
                    current_control = control_id
                    current_questions = []
                    
                    # Add implementation questions for this control
                    current_questions.extend([
                        {
                            'id': f"{control_id}_imp_1",
                            'question': f"Is control {control_id} ({values[2]}) implemented?",
                            'type': 'boolean'
                        },
                        {
                            'id': f"{control_id}_imp_2",
                            'question': "What evidence supports this implementation?",
                            'type': 'text'
                        },
                        {
                            'id': f"{control_id}_imp_3",
                            'question': "When was this control last reviewed?",
                            'type': 'date'
                        },
                        {
                            'id': f"{control_id}_imp_4",
                            'question': "What is the maturity level of this control?",
                            'type': 'choice',
                            'options': ['Not Implemented', 'Initial', 'Managed', 'Defined', 'Measured', 'Optimized']
                        }
                    ])
            
            if current_control:
                questions[current_control] = current_questions
                
        except Exception as e:
            print(f"Error loading CIS RAM questions: {e}")
            import traceback
            traceback.print_exc()
        
        return questions
    
    def ask_questions(self, control_id: str) -> Dict:
        """Ask questions for a specific control and store responses"""
        if control_id not in self.questions:
            return {}
            
        responses = {}
        print(f"\nAssessing CIS RAM Control {control_id}:")
        
        for question in self.questions[control_id]:
            print(f"\n{question['question']}")
            
            if question['type'] == 'boolean':
                response = input("Enter 'yes' or 'no': ").lower().strip()
                responses[question['id']] = response == 'yes'
            
            elif question['type'] == 'text':
                response = input("Enter your response: ").strip()
                responses[question['id']] = response
            
            elif question['type'] == 'date':
                response = input("Enter date (YYYY-MM-DD): ").strip()
                responses[question['id']] = response
            
            elif question['type'] == 'choice':
                print("Options:", ', '.join(question['options']))
                response = input("Enter your choice: ").strip()
                if response in question['options']:
                    responses[question['id']] = response
                else:
                    print("Invalid choice. Defaulting to 'Not Implemented'")
                    responses[question['id']] = 'Not Implemented'
        
        self.responses[control_id] = responses
        return responses
    
    def get_control_maturity_score(self, control_id: str) -> float:
        """Calculate maturity score for a control based on responses"""
        if control_id not in self.responses:
            return 0.0
            
        responses = self.responses[control_id]
        maturity_levels = {
            'Not Implemented': 0.0,
            'Initial': 0.2,
            'Managed': 0.4,
            'Defined': 0.6,
            'Measured': 0.8,
            'Optimized': 1.0
        }
        
        # Get maturity level response
        maturity_question_id = f"{control_id}_imp_4"
        maturity_level = responses.get(maturity_question_id, 'Not Implemented')
        
        # Calculate score
        implementation_score = 1.0 if responses.get(f"{control_id}_imp_1", False) else 0.0
        evidence_score = 0.5 if responses.get(f"{control_id}_imp_2", "").strip() else 0.0
        review_score = 0.5 if responses.get(f"{control_id}_imp_3", "").strip() else 0.0
        
        base_score = (implementation_score + evidence_score + review_score) / 2
        maturity_multiplier = maturity_levels.get(maturity_level, 0.0)
        
        return base_score * maturity_multiplier

class VulnerabilityScanner:
    def __init__(self):
        """Initialize vulnerability scanner"""
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cpe_match_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        
    def get_installed_software(self) -> List[Dict]:
        """Get list of installed applications and their versions"""
        apps = []
        
        # Get apps from /Applications
        stdout, success = self._safe_run_command(['find', '/Applications', '-name', '*.app'])
        if success:
            for app_path in stdout.split('\n'):
                if app_path:
                    info_plist = os.path.join(app_path, 'Contents/Info.plist')
                    if os.path.exists(info_plist):
                        try:
                            with open(info_plist, 'rb') as f:
                                plist_data = plistlib.load(f)
                                apps.append({
                                    'name': plist_data.get('CFBundleName', os.path.basename(app_path)),
                                    'version': plist_data.get('CFBundleShortVersionString', 'Unknown'),
                                    'path': app_path,
                                    'bundle_id': plist_data.get('CFBundleIdentifier', '')
                                })
                        except:
                            pass
        
        # Get Homebrew packages
        stdout, success = self._safe_run_command(['brew', 'list', '--versions'])
        if success:
            for line in stdout.split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        apps.append({
                            'name': parts[0],
                            'version': parts[1],
                            'path': f'/opt/homebrew/Cellar/{parts[0]}/',
                            'source': 'homebrew'
                        })
        
        return apps
    
    def check_vulnerabilities(self, apps: List[Dict]) -> List[Dict]:
        """Check for known vulnerabilities in installed applications"""
        results = []
        
        for app in apps:
            vulnerabilities = []
            
            # Check NVD database
            cpe_query = f"cpe:2.3:a:*:{app['name']}:{app['version']}:*:*:*:*:*:*:*"
            params = {
                'cpeName': cpe_query,
                'resultsPerPage': 100
            }
            
            try:
                response = requests.get(self.nvd_api_url, params=params)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        if cve:
                            vulnerabilities.append({
                                'id': cve.get('id', ''),
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                                'published': cve.get('published', '')
                            })
            except Exception as e:
                print(f"Error checking vulnerabilities for {app['name']}: {e}")
            
            if vulnerabilities:
                results.append({
                    'app_name': app['name'],
                    'version': app['version'],
                    'vulnerabilities': vulnerabilities
                })
        
        return results
    
    def _safe_run_command(self, command: List[str], requires_sudo: bool = False) -> Tuple[str, bool]:
        """Safely run a command and return its output"""
        try:
            if requires_sudo:
                command.insert(0, 'sudo')
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout.strip(), result.returncode == 0
        except Exception as e:
            return str(e), False

class MacDeviceScanner:
    def __init__(self):
        """Initialize the scanner"""
        self.today = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.project_dir = Path(__file__).parent.parent
        self.reports_dir = self.project_dir / 'reports'
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Load CIS RAM controls
        cis_ram_path = self.project_dir / 'scripts/cis_ram_questions.json'
        self.cis_ram = CISRAMChecker(str(cis_ram_path))
        self.cis_ram_questionnaire = CISRAMQuestionnaire(str(cis_ram_path))
        
        self.report_data = {
            'system_info': {},
            'vulnerabilities': [],
            'cis_level1': {},
            'cis_level2': {},
            'cis_level3': {},
            'cis_ram': {}
        }
        
    def check_prerequisites(self):
        """Display scanner information"""
        print("\n=== Security Scanner Information ===")
        print("This scanner will check your system security settings and may require:")
        print("1. Administrator (sudo) privileges for some checks")
        print("2. Keychain access for certificate and security checks\n")
        
        print("The following checks will be performed:")
        print("- System configuration")
        print("- Security settings")
        print("- DNS configuration")
        print("- Certificate validation")
        print("- CIS compliance checks\n")
        
    def _safe_run_command(self, command: List[str], requires_sudo: bool = False) -> subprocess.CompletedProcess:
        """Safely run commands with proper permission handling"""
        if requires_sudo:
            command = ['sudo'] + command
            
        try:
            return subprocess.run(command, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {' '.join(command)}")
            print(f"Error: {str(e)}")
            return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(e))

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
        results_dir = self.reports_dir
        results_dir.mkdir(exist_ok=True)
        
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
        report_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_path = self.reports_dir / f"security_report_{report_time}.txt"
        json_path = self.reports_dir / f"security_report_{report_time}.json"
        
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
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Level 2 Results
            f.write("\nLevel 2 (Advanced) Checks:\n")
            level2_score = sum(c['score'] for c in level2_checks)
            level2_max = 7
            f.write(f"Score: {(level2_score/level2_max)*100:.1f}%\n")
            for check in level2_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Level 3 Results
            f.write("\nLevel 3 (Enterprise) Checks:\n")
            level3_score = sum(c['score'] for c in level3_checks)
            level3_max = 11
            f.write(f"Score: {(level3_score/level3_max)*100:.1f}%\n")
            for check in level3_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
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
            total_max = level1_max + level2_max + level3_max
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
                'cis_compliance': {
                    'level1': {'checks': level1_checks, 'score': (level1_score/level1_max)*100},
                    'level2': {'checks': level2_checks, 'score': (level2_score/level2_max)*100},
                    'level3': {'checks': level3_checks, 'score': (level3_score/level3_max)*100},
                    'overall_score': overall_percent
                },
                'network_security': network_checks,
                'process_security': process_checks,
                'vulnerabilities': vuln_results,
                'cis_ram_results': cis_ram_results
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
                'status': 'pass' if 'enabled' in updates.stdout.lower() else 'fail',
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
        stdout, success = self._safe_run_command(['defaults', 'read', '/Library/Preferences/com.apple.Bluetooth', 'ControllerPowerState'])
        is_bluetooth_disabled = success and '0' in stdout
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
        report_dir = Path(self.reports_dir)
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
                capture_output=True, text=True
            )
            return result.stdout.strip() == '1'
        except Exception:
            return False

    def _is_autoupdate_enabled(self) -> bool:
        """Check if automatic updates are enabled"""
        try:
            result = subprocess.run(
                ['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate.plist', 'AutomaticCheckEnabled'],
                capture_output=True, text=True
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
        failed_checks = len([c for c in results['checks'] if c['status'] == 'fail'])
        
        risk_score = (passed_checks / total_checks) * 100
        
        summary.append("\n=== Executive Summary ===\n")
        summary.append(f"Security Risk Score: {risk_score:.1f}%")
        summary.append(f"Total Checks: {total_checks}")
        summary.append(f"Passed: {passed_checks}")
        summary.append(f"Failed: {failed_checks}")
        
        if failed_checks > 0:
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
        try:
            self.check_prerequisites()
            
            # Part 1: System Information
            print("\n=== System Information ===")
            system_info = self.get_system_info()
            self.report_data['system_info'] = system_info
            
            # Part 2: Vulnerability Scanning
            print("\n=== Vulnerability Scanning ===")
            vuln_scanner = VulnerabilityScanner()
            installed_apps = vuln_scanner.get_installed_software()
            vulnerabilities = vuln_scanner.check_vulnerabilities(installed_apps)
            self.report_data['vulnerabilities'] = vulnerabilities
            
            # Part 3: CIS Level 1 Compliance
            print("\n=== CIS Level 1 Compliance Checks ===")
            cis_level1_results = self.check_cis_level1()
            self.report_data['cis_level1'] = cis_level1_results
            
            # Part 4: CIS Level 2 Compliance
            print("\n=== CIS Level 2 Compliance Checks ===")
            cis_level2_results = self.check_cis_level2()
            self.report_data['cis_level2'] = cis_level2_results
            
            # Part 5: CIS Level 3 Compliance
            print("\n=== CIS Level 3 Compliance Checks ===")
            cis_level3_results = self.check_cis_level3()
            self.report_data['cis_level3'] = cis_level3_results
            
            # Part 6: CIS RAM Assessment
            print("\n=== CIS RAM Assessment ===")
            cis_ram_results = self.assess_cis_ram_controls()
            self.report_data['cis_ram'] = cis_ram_results
            
            # Generate Report
            self.generate_report()
            
        except Exception as e:
            print(f"Error during scan: {e}")
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
        
        # 1. Password Policy
        self._check_password_policy(results)
        
        # 2. Screen Saver Settings
        self._check_screen_saver(results)
        
        # 3. Automatic Login
        self._check_auto_login(results)
        
        # 4. Guest Account
        self._check_guest_account(results)
        
        # 5. Remote Login
        self._check_remote_login(results)
        
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
        report_path = self.project_dir / f'reports/security_report_{timestamp}.txt'
        json_path = self.project_dir / f'reports/security_report_{timestamp}.json'
        
        with open(report_path, 'w') as f:
            f.write("=== macOS Security Assessment Report ===\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # System Information
            f.write("=== System Information ===\n")
            if 'ProductName' in self.report_data['system_info']:
                f.write(f"OS: {self.report_data['system_info'].get('ProductName', 'Unknown')} {self.report_data['system_info'].get('ProductVersion', 'Unknown')}\n")
            if 'Model Name' in self.report_data['system_info']:
                f.write(f"Model: {self.report_data['system_info'].get('Model Name', 'Unknown')}\n")
            if 'Processor Name' in self.report_data['system_info']:
                f.write(f"Processor: {self.report_data['system_info'].get('Processor Name', 'Unknown')}\n")
            if 'Memory' in self.report_data['system_info']:
                f.write(f"Memory: {self.report_data['system_info'].get('Memory', 'Unknown')}\n")
            
            # Disk Space Information
            if 'disk_space' in self.report_data['system_info']:
                f.write("\n=== Disk Space Information ===\n")
                for disk in self.report_data['system_info']['disk_space']:
                    f.write(f"\nFilesystem: {disk['filesystem']}\n")
                    f.write(f"Size: {disk['size']}\n")
                    f.write(f"Used: {disk['used']} ({disk['capacity']})\n")
                    f.write(f"Available: {disk['available']}\n")
                    f.write(f"Mounted on: {disk['mounted_on']}\n")
            
            # CIS Compliance Results
            f.write("\n=== CIS Compliance Results ===\n")
            
            # Group checks by level
            level1_checks = [c for c in self.report_data['cis_level1']['checks']]
            level2_checks = [c for c in self.report_data['cis_level2']['checks']]
            level3_checks = [c for c in self.report_data['cis_level3']['checks']]
            
            # Level 1 Results
            f.write("\nLevel 1 (Basic) Checks:\n")
            level1_score = self.report_data['cis_level1']['score']
            f.write(f"Score: {level1_score:.1f}%\n")
            for check in level1_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Level 2 Results
            f.write("\nLevel 2 (Advanced) Checks:\n")
            level2_score = self.report_data['cis_level2']['score']
            f.write(f"Score: {level2_score:.1f}%\n")
            for check in level2_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Level 3 Results
            f.write("\nLevel 3 (Enterprise) Checks:\n")
            level3_score = self.report_data['cis_level3']['score']
            f.write(f"Score: {level3_score:.1f}%\n")
            for check in level3_checks:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Network Security
            f.write("\n=== Network Security ===\n")
            for check in self.report_data['network_checks']:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Process Security
            f.write("\n=== Process Security ===\n")
            for check in self.report_data['process_checks']:
                status = "✓" if check['status'] else "✗"
                f.write(f"{status} {check['name']}: {check['details']}\n")
            
            # Vulnerabilities
            f.write("\n=== Vulnerability Assessment ===\n")
            if self.report_data['vulnerabilities']:
                for vuln in self.report_data['vulnerabilities']:
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
            if self.report_data['cis_ram']:
                f.write("\n=== CIS RAM Assessment ===\n")
                for result in self.report_data['cis_ram']['controls'].values():
                    f.write(f"\nControl {result['responses']['1.1_imp_1']}: {result['score']:.2f}\n")
            
            # Executive Summary
            f.write("\n=== Executive Summary ===\n")
            total_score = level1_score + level2_score + level3_score
            total_max = 40 + 7 + 11
            overall_percent = (total_score / total_max) * 100
            f.write(f"Overall Security Score: {overall_percent:.1f}%\n")
            f.write(f"CIS Level 1 (Basic) Score: {level1_score:.1f}%\n")
            f.write(f"CIS Level 2 (Advanced) Score: {level2_score:.1f}%\n")
            f.write(f"CIS Level 3 (Enterprise) Score: {level3_score:.1f}%\n")
            
            vuln_count = sum(len(v.get('vulnerabilities', [])) for v in self.report_data['vulnerabilities'])
            f.write(f"Total Vulnerabilities Found: {vuln_count}\n")
            
            # Save as JSON for machine processing
            json_data = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self.report_data['system_info'],
                'cis_compliance': {
                    'level1': {'checks': level1_checks, 'score': level1_score},
                    'level2': {'checks': level2_checks, 'score': level2_score},
                    'level3': {'checks': level3_checks, 'score': level3_score},
                    'overall_score': overall_percent
                },
                'network_security': self.report_data['network_checks'],
                'process_security': self.report_data['process_checks'],
                'vulnerabilities': self.report_data['vulnerabilities'],
                'cis_ram_results': self.report_data['cis_ram']
            }
            
            with open(json_path, 'w') as jf:
                json.dump(json_data, jf, indent=2)
            print(f"JSON data saved: {json_path}")

def main():
    scanner = MacDeviceScanner()
    print("Starting macOS security scan...")
    
    # Check prerequisites and get user consent
    scanner.check_prerequisites()
    
    try:
        # Run basic checks first (no keychain/sudo required)
        print("\nRunning Basic Security Checks...")
        results = {
            'checks': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # System Configuration
        print("\n1. Checking System Configuration...")
        results['checks'].extend(scanner._check_cis_level1())
        
        # Network Security
        print("\n2. Checking Network Security...")
        dns_info = scanner.check_dns_history()
        results['dns_info'] = dns_info
        
        # Generate recommendations
        print("\n3. Generating Security Recommendations...")
        recommendations = scanner.generate_recommendations(results)
        
        # Save comprehensive report
        print("\n4. Saving Detailed Report...")
        scanner.save_report(results, recommendations)
        
        # Display executive summary
        print("\n5. Security Assessment Complete!")
        print(scanner.generate_executive_summary(results))
        
        print(f"\nDetailed report saved to: {scanner.reports_dir}/security_report_{scanner.today}.md")
        
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()