#!/bin/bash

# Function to collect system information
collect_system_info() {
    echo "System Information"
    echo "=================="
    
    # Basic System Info
    echo "Hostname: $(scutil --get ComputerName)"
    echo "Local Hostname: $(scutil --get LocalHostName)"
    echo "Model: $(system_profiler SPHardwareDataType | grep "Model Name" | cut -d: -f2- | xargs)"
    echo "Model Identifier: $(system_profiler SPHardwareDataType | grep "Model Identifier" | cut -d: -f2- | xargs)"
    echo "Serial Number: $(system_profiler SPHardwareDataType | grep "Serial Number" | cut -d: -f2- | xargs)"
    echo "macOS Version: $(sw_vers -productVersion)"
    echo "Build Version: $(sw_vers -buildVersion)"
    
    # CPU & Memory
    echo -e "\nProcessor & Memory"
    echo "------------------"
    echo "Processor: $(sysctl -n machdep.cpu.brand_string)"
    echo "CPU Cores: $(sysctl -n hw.ncpu)"
    echo "Memory: $(system_profiler SPHardwareDataType | grep "Memory:" | cut -d: -f2- | xargs)"
    
    # Storage Information
    echo -e "\nStorage Information"
    echo "-------------------"
    echo "Disk Usage:"
    df -h / | tail -n 1 | awk '{print "Total: " $2 ", Used: " $3 ", Free: " $4 ", Use%: " $5}'
    
    # Network Interfaces
    echo -e "\nNetwork Information"
    echo "-------------------"
    echo "Local IP Addresses:"
    ipconfig getifaddr en0 2>/dev/null && echo "Wi-Fi (en0): $(ipconfig getifaddr en0)"
    ipconfig getifaddr en1 2>/dev/null && echo "Ethernet (en1): $(ipconfig getifaddr en1)"
    
    # Public IP (if internet is available)
    echo "Public IP: $(curl -s https://api.ipify.org 2>/dev/null || echo "Unable to determine")"
    
    # Active Network Services
    echo -e "\nActive Network Services:"
    networksetup -listallnetworkservices | grep -v "*" | while read -r service; do
        if networksetup -getinfo "$service" | grep -q "IP address:" 2>/dev/null; then
            echo "$service: Active"
        fi
    done
    
    # Security & Encryption Status
    echo -e "\nSecurity Information"
    echo "-------------------"
    echo "FileVault Status: $(fdesetup status | cut -d. -f1)"
    echo "SIP Status: $(csrutil status | cut -d: -f2- | xargs)"
    
    # Power Information
    echo -e "\nPower Information"
    echo "-----------------"
    if system_profiler SPPowerDataType | grep -q "Battery"; then
        system_profiler SPPowerDataType | grep -A 5 "Battery Information" | grep -E "Cycle Count|Condition|Charging"
    else
        echo "No battery detected (Desktop Mac)"
    fi
    
    # Hardware Ports
    echo -e "\nHardware Ports"
    echo "--------------"
    system_profiler SPUSBDataType | grep -A 2 "USB 3" | grep -v "Speed:"
    
    # Installed Applications
    echo -e "\nInstalled Applications Summary"
    echo "---------------------------"
    echo "Total Apps in /Applications: $(ls -l /Applications | grep -c "^d")"
    echo "Recently Modified Apps (last 30 days):"
    find /Applications -type d -maxdepth 1 -mtime -30 | grep -v "^/Applications$" | while read -r app; do
        echo "- $(basename "$app")"
    done
    
    echo -e "\n===================="
}

# Add system information to the report
collect_system_info > system_info.txt

# CIS macOS Security Check Script
# Based on CIS Apple macOS 12.0 Monterey Benchmark v4.0.0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
level1_checks=0
level2_checks=0

# Arrays to store results
declare -a check_names
declare -a check_results
declare -a check_levels
declare -a check_remediations

# Function to print section headers
print_section() {
    echo -e "\n${BOLD}$1${NC}"
    echo "----------------------------------------"
}

# Function to check a security setting
check_security_item() {
    local check_name="$1"
    local command="$2"
    local expected_result="$3"
    local remediation="$4"
    local level="$5"
    
    # Store check details
    check_names+=("$check_name")
    check_remediations+=("$remediation")
    
    # Increment total checks
    ((total_checks++))
    
    # Track check level
    if [ "$level" = "Level 1" ]; then
        ((level1_checks++))
    elif [ "$level" = "Level 2" ]; then
        ((level2_checks++))
    fi
    
    # Run the check command
    local result
    result=$(eval "$command" 2>/dev/null || echo "error")
    
    # Compare result with expected
    if [ "$result" = "$expected_result" ]; then
        echo -e "${GREEN}[Pass]${NC} $check_name"
        check_results+=("Pass")
        ((passed_checks++))
    else
        echo -e "${RED}[Fail]${NC} $check_name"
        echo -e "${YELLOW}Remediation:${NC} $remediation"
        check_results+=("Fail")
        ((failed_checks++))
    fi
    check_levels+=("$level")
}

# Get the absolute path to the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS_DIR="$PROJECT_ROOT/reports"

# Create report directory if it doesn't exist
mkdir -p "$REPORTS_DIR"

# Generate timestamp for report file
timestamp=$(date +"%Y%m%d_%H%M%S")
report_file="$REPORTS_DIR/cis_security_report_${timestamp}.txt"

# Combine system information with the report
{
    echo "CIS macOS Security Benchmark Report"
    echo "=================================="
    echo "Generated on: $(date)"
    echo ""
    
    # Add system information
    cat system_info.txt
    echo ""
    echo "Security Check Results"
    echo "====================="
    echo ""
} > "$report_file"

# Append the rest of the report and clean up
exec 1> >(tee -a "$report_file") 2>&1

# Print header
echo "CIS macOS Security Benchmark v4.0.0 - $(date)"
echo "=================================================="
echo ""

# 1. Install Updates, Patches and Additional Security Software
print_section "1. System Updates and Security Software"

# 1.1 Ensure all Apple-provided software is current
check_security_item \
    "1.1 Ensure all Apple-provided software is current" \
    "softwareupdate -l | grep -c 'No new software available.'" \
    "1" \
    "Run 'softwareupdate -i -a' to install all available updates" \
    "Level 1"

# 1.2 Ensure Auto Update is enabled
check_security_item \
    "1.2 Ensure Auto Update is enabled" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled" \
    "1" \
    "Enable automatic updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1" \
    "Level 1"

# 1.3 Ensure Download new updates when available is enabled
check_security_item \
    "1.3 Ensure Download new updates when available is enabled" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload" \
    "1" \
    "Enable automatic download: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -int 1" \
    "Level 1"

# 1.4 Ensure Installation of macOS updates is enabled
check_security_item \
    "1.4 Ensure Installation of macOS updates is enabled" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates" \
    "1" \
    "Enable automatic macOS updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -int 1" \
    "Level 1"

# 1.5 Ensure System data files and Security updates are installed
check_security_item \
    "1.5 Ensure System data files and Security updates are installed" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall && defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall" \
    "1" \
    "Enable system data and security updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -int 1 && sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -int 1" \
    "Level 1"

# 2. System Preferences
print_section "2. System Preferences"

# 2.1 Bluetooth
check_security_item \
    "2.1.1 Disable Bluetooth if no paired devices exist" \
    "system_profiler SPBluetoothDataType | grep -c 'Paired: Yes' || defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState" \
    "0" \
    "Disable Bluetooth if not needed: sudo defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0" \
    "Level 2"

check_security_item \
    "2.1.2 Show Bluetooth status in menu bar" \
    "defaults read com.apple.controlcenter 'NSStatusItem Visible Bluetooth'" \
    "1" \
    "Show Bluetooth in menu bar: defaults write com.apple.controlcenter 'NSStatusItem Visible Bluetooth' -int 1" \
    "Level 1"

# 2.2 Date & Time
check_security_item \
    "2.2.1 Enable Set time and date automatically" \
    "systemsetup -getusingnetworktime | grep -c 'Network Time: On'" \
    "1" \
    "Enable network time: sudo systemsetup -setusingnetworktime on" \
    "Level 1"

check_security_item \
    "2.2.2 Ensure time set is within appropriate limits" \
    "sntp -sS time.apple.com > /dev/null 2>&1; echo $?" \
    "0" \
    "Sync time with Apple's time server: sudo sntp -sS time.apple.com" \
    "Level 1"

# 2.3 Desktop & Screen Saver
check_security_item \
    "2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver" \
    "defaults read com.apple.screensaver idleTime 2>/dev/null | awk '{exit ($1 > 1200)}'" \
    "0" \
    "Set screen saver timeout: defaults write com.apple.screensaver idleTime -int 1200" \
    "Level 1"

check_security_item \
    "2.3.2 Secure screen saver corners" \
    "defaults read com.apple.dock wvous-tl-corner 2>/dev/null | grep -c '^6$'" \
    "0" \
    "Disable hot corners for screen saver: defaults write com.apple.dock wvous-tl-corner -int 0" \
    "Level 2"

# 2.4 Sharing
check_security_item \
    "2.4.1 Disable Remote Apple Events" \
    "systemsetup -getremoteappleevents | grep -c 'Remote Apple Events: Off'" \
    "1" \
    "Disable remote apple events: sudo systemsetup -setremoteappleevents off" \
    "Level 1"

check_security_item \
    "2.4.2 Disable Internet Sharing" \
    "defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -c 'Enabled = 1'" \
    "0" \
    "Disable Internet Sharing in System Preferences > Sharing" \
    "Level 1"

check_security_item \
    "2.4.3 Disable Screen Sharing" \
    "launchctl print-disabled system/com.apple.screensharing | grep -c 'disabled => true'" \
    "1" \
    "Disable Screen Sharing: sudo launchctl disable system/com.apple.screensharing" \
    "Level 1"

# 2.5 Energy Saver
check_security_item \
    "2.5.1 Disable wake for network access" \
    "pmset -g | grep -c 'womp                 0'" \
    "1" \
    "Disable wake for network access: sudo pmset -a womp 0" \
    "Level 2"

check_security_item \
    "2.5.2 Disable Power Nap" \
    "pmset -g | grep -c 'powernap             0'" \
    "1" \
    "Disable Power Nap: sudo pmset -a powernap 0" \
    "Level 2"

# 2.6 Time Machine
check_security_item \
    "2.6.1 Enable Time Machine" \
    "defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup" \
    "1" \
    "Enable Time Machine backups: sudo defaults write /Library/Preferences/com.apple.TimeMachine AutoBackup -int 1" \
    "Level 1"

check_security_item \
    "2.6.2 Enable Time Machine encryption" \
    "defaults read /Library/Preferences/com.apple.TimeMachine RequiresEncryption" \
    "1" \
    "Enable Time Machine encryption: sudo defaults write /Library/Preferences/com.apple.TimeMachine RequiresEncryption -int 1" \
    "Level 1"

# 2.7 Login Window
check_security_item \
    "2.7.1 Disable automatic login" \
    "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null | grep -c 'does not exist'" \
    "1" \
    "Disable automatic login: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser" \
    "Level 1"

check_security_item \
    "2.7.2 Disable guest account login" \
    "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled" \
    "0" \
    "Disable guest account: sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO" \
    "Level 1"

check_security_item \
    "2.7.3 Disable Show password hints" \
    "defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint" \
    "0" \
    "Disable password hints: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" \
    "Level 1"

# 3. Logging and Auditing
print_section "3. Logging and Auditing"

# 3.1 Configure asl.conf
check_security_item \
    "3.1.1 Ensure security auditing is enabled" \
    "launchctl list | grep -c auditd" \
    "1" \
    "Enable security auditing: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist" \
    "Level 1"

check_security_item \
    "3.1.2 Ensure install.log exists and is configured properly" \
    "ls /var/log/install.log 2>/dev/null | grep -c install.log" \
    "1" \
    "Create install.log: sudo touch /var/log/install.log && sudo chmod 644 /var/log/install.log" \
    "Level 1"

# 3.2 Configure syslog
check_security_item \
    "3.2.1 Ensure system log files exist and are configured properly" \
    "ls -l /etc/newsyslog.conf 2>/dev/null | grep -c '^-rw-r--r--'" \
    "1" \
    "Configure syslog: sudo chmod 644 /etc/newsyslog.conf" \
    "Level 1"

check_security_item \
    "3.2.2 Ensure security auditing retention" \
    "grep -c expire-after /etc/security/audit_control" \
    "1" \
    "Configure audit retention: sudo vi /etc/security/audit_control and add 'expire-after:60d'" \
    "Level 1"

# 3.3 Retain install.log for 365 or more days
check_security_item \
    "3.3.1 Ensure install.log retention" \
    "grep -c ttl /etc/asl/com.apple.install | grep -c '365'" \
    "1" \
    "Set install.log retention: sudo vi /etc/asl/com.apple.install and add 'ttl=365'" \
    "Level 1"

# 3.4 Ensure security auditing retention
check_security_item \
    "3.4.1 Ensure audit files are retained for at least 60 days" \
    "grep -c 'expire-after:60d' /etc/security/audit_control" \
    "1" \
    "Set audit retention: sudo vi /etc/security/audit_control and ensure expire-after:60d is set" \
    "Level 1"

check_security_item \
    "3.4.2 Ensure old audit logs are closed" \
    "grep -c flags /etc/security/audit_control" \
    "1" \
    "Configure audit flags: sudo vi /etc/security/audit_control and add appropriate flags" \
    "Level 1"

# 3.5 Control access to audit records
check_security_item \
    "3.5.1 Ensure audit folder has appropriate permissions" \
    "ls -ld /var/audit | grep -c '^drwx------'" \
    "1" \
    "Set audit folder permissions: sudo chmod 700 /var/audit" \
    "Level 1"

check_security_item \
    "3.5.2 Ensure audit files have appropriate permissions" \
    "find /var/audit -type f -exec ls -l {} \; | grep -vc '^-rw-------'" \
    "0" \
    "Set audit file permissions: sudo find /var/audit -type f -exec chmod 600 {} \;" \
    "Level 1"

# 3.6 Enable Security Auditing
check_security_item \
    "3.6.1 Ensure audit service is running" \
    "sudo audit -c | grep -c 'AUC_AUDITING'" \
    "1" \
    "Start audit service: sudo audit -s" \
    "Level 1"

check_security_item \
    "3.6.2 Ensure audit statistics are properly configured" \
    "grep -c minfree /etc/security/audit_control" \
    "1" \
    "Configure audit statistics: sudo vi /etc/security/audit_control and set minfree:25" \
    "Level 1"

check_security_item \
    "3.6.3 Ensure audit settings are configured properly" \
    "grep -c policy /etc/security/audit_control" \
    "1" \
    "Configure audit policy: sudo vi /etc/security/audit_control and set appropriate policy" \
    "Level 1"

check_security_item \
    "3.6.4 Ensure login/logout events are logged" \
    "grep -c '^flags:.*fm' /etc/security/audit_control" \
    "1" \
    "Enable login/logout auditing: sudo vi /etc/security/audit_control and add 'fm' to flags" \
    "Level 1"

check_security_item \
    "3.6.5 Ensure audit logs are not deleted" \
    "grep -c keep-alive /etc/security/audit_control" \
    "1" \
    "Prevent audit log deletion: sudo vi /etc/security/audit_control and add keep-alive" \
    "Level 1"

# 4. Network Configurations
print_section "4. Network Configurations"

# 4.1 Disable Bonjour advertising service
check_security_item \
    "4.1.1 Disable Bonjour advertising service" \
    "defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements" \
    "1" \
    "Disable Bonjour advertising: sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES" \
    "Level 2"

# 4.2 Enable "Show Wi-Fi status in menu bar"
check_security_item \
    "4.2.1 Show Wi-Fi status in menu bar" \
    "defaults read com.apple.controlcenter 'NSStatusItem Visible WiFi'" \
    "1" \
    "Show Wi-Fi in menu bar: defaults write com.apple.controlcenter 'NSStatusItem Visible WiFi' -int 1" \
    "Level 1"

# 4.3 Disable Remote Apple Events
check_security_item \
    "4.3.1 Disable Remote Apple Events" \
    "systemsetup -getremoteappleevents | grep -c 'Remote Apple Events: Off'" \
    "1" \
    "Disable Remote Apple Events: sudo systemsetup -setremoteappleevents off" \
    "Level 1"

# 4.4 Disable Remote Login
check_security_item \
    "4.4.1 Disable Remote Login (SSH)" \
    "systemsetup -getremotelogin | grep -c 'Remote Login: Off'" \
    "1" \
    "Disable Remote Login: sudo systemsetup -setremotelogin off" \
    "Level 1"

check_security_item \
    "4.4.2 Ensure SSH KeyBased Authentication is enabled" \
    "grep -c '^PasswordAuthentication no' /etc/ssh/sshd_config" \
    "1" \
    "Enable SSH key authentication: Add 'PasswordAuthentication no' to /etc/ssh/sshd_config" \
    "Level 1"

# 4.5 Disable File Sharing
check_security_item \
    "4.5.1 Disable AFP" \
    "launchctl print-disabled system/com.apple.AppleFileServer | grep -c 'disabled => true'" \
    "1" \
    "Disable AFP: sudo launchctl disable system/com.apple.AppleFileServer" \
    "Level 1"

check_security_item \
    "4.5.2 Disable SMB" \
    "launchctl print-disabled system/com.apple.smbd | grep -c 'disabled => true'" \
    "1" \
    "Disable SMB: sudo launchctl disable system/com.apple.smbd" \
    "Level 1"

# 4.6 Disable Remote Management
check_security_item \
    "4.6.1 Disable ARD Agent and Remote Desktop" \
    "ps aux | grep -c '[A]RDAgent'" \
    "0" \
    "Disable ARD Agent: sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop" \
    "Level 1"

# 4.7 Enable Firewall
check_security_item \
    "4.7.1 Enable Application Firewall" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -c 'enabled'" \
    "1" \
    "Enable Firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" \
    "Level 1"

check_security_item \
    "4.7.2 Enable Firewall Logging" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | grep -c 'on'" \
    "1" \
    "Enable Firewall Logging: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on" \
    "Level 1"

check_security_item \
    "4.7.3 Enable Firewall Stealth Mode" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -c 'enabled'" \
    "1" \
    "Enable Stealth Mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" \
    "Level 1"

# 4.8 Enable Firewall Stealth Mode
check_security_item \
    "4.8.1 Block all incoming connections" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall | grep -c 'enabled'" \
    "1" \
    "Block all incoming: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on" \
    "Level 2"

check_security_item \
    "4.8.2 Automatically allow signed built-in software" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned | grep -c 'DISABLED'" \
    "0" \
    "Allow signed software: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on" \
    "Level 1"

# 5. System Access, Authentication and Authorization
print_section "5. System Access, Authentication and Authorization"

# 5.1 File System Permissions and Access Controls
check_security_item \
    "5.1.1 Secure Home Folders" \
    "find /Users -type d -maxdepth 1 -mindepth 1 -exec ls -ld {} \; | grep -vc '^ *drwx------ '" \
    "0" \
    "Secure home folders: sudo chmod 700 /Users/*/" \
    "Level 1"

check_security_item \
    "5.1.2 Check System Wide Applications" \
    "ls -l /Applications/ | grep -c '^drwxr-xr-x'" \
    "1" \
    "Set Applications permissions: sudo chmod 755 /Applications/*" \
    "Level 1"

check_security_item \
    "5.1.3 Check System Folder Permissions" \
    "ls -l / | grep -c '^drwxr-xr-x.*System'" \
    "1" \
    "Set System folder permissions: sudo chmod 755 /System" \
    "Level 1"

# 5.2 Password Requirements
check_security_item \
    "5.2.1 Configure account lockout threshold" \
    "pwpolicy -getaccountpolicies 2>/dev/null | grep -A1 'policyAttributeMaximumFailedAuthentications' | grep -c '<integer>5</integer>'" \
    "1" \
    "Set account lockout threshold: pwpolicy -setaccountpolicies" \
    "Level 1"

check_security_item \
    "5.2.2 Set a minimum password length" \
    "pwpolicy -getaccountpolicies 2>/dev/null | grep -A1 'policyAttributePassword' | grep -c '<integer>15</integer>'" \
    "1" \
    "Set minimum password length: pwpolicy -setaccountpolicies" \
    "Level 1"

check_security_item \
    "5.2.3 Complex passwords must contain an Alphabetic Character" \
    "pwpolicy -getaccountpolicies 2>/dev/null | grep -c 'policyAttributePasswordHasAlpha'" \
    "1" \
    "Require alphabetic characters: pwpolicy -setaccountpolicies" \
    "Level 1"

# 5.3 Reduce the sudo timeout period
check_security_item \
    "5.3.1 Set sudo timeout period to 0" \
    "grep -c '^Defaults.*timestamp_timeout=0' /etc/sudoers" \
    "1" \
    "Set sudo timeout: sudo visudo and add 'Defaults timestamp_timeout=0'" \
    "Level 1"

# 5.4 Use a separate timestamp for each user/tty combo
check_security_item \
    "5.4.1 Enable tty_tickets for sudo" \
    "grep -c '^Defaults.*tty_tickets' /etc/sudoers" \
    "1" \
    "Enable tty_tickets: sudo visudo and add 'Defaults tty_tickets'" \
    "Level 1"

# 5.5 Automatically lock the login keychain
check_security_item \
    "5.5.1 Enable auto-lock for login keychain" \
    "security show-keychain-info ~/Library/Keychains/login.keychain 2>&1 | grep -c 'no-timeout'" \
    "0" \
    "Enable keychain auto-lock: security set-keychain-settings ~/Library/Keychains/login.keychain" \
    "Level 1"

# 5.6 Ensure login keychain is locked when the computer sleeps
check_security_item \
    "5.6.1 Lock keychain on sleep" \
    "security show-keychain-info ~/Library/Keychains/login.keychain 2>&1 | grep -c 'lock-on-sleep'" \
    "1" \
    "Enable keychain lock on sleep: security set-keychain-settings -l ~/Library/Keychains/login.keychain" \
    "Level 1"

# 5.7 Do not enable the "root" account
check_security_item \
    "5.7.1 Disable root account" \
    "dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -c 'No such key'" \
    "1" \
    "Disable root account: sudo dscl . -delete /Users/root AuthenticationAuthority" \
    "Level 1"

# 5.8 Disable automatic login
check_security_item \
    "5.8.1 Ensure automatic login is disabled" \
    "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1 | grep -c 'does not exist'" \
    "1" \
    "Disable automatic login: sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser" \
    "Level 1"

# 5.9 Require a password to wake the computer from sleep or screen saver
check_security_item \
    "5.9.1 Require password after sleep or screen saver" \
    "defaults read com.apple.screensaver askForPassword" \
    "1" \
    "Enable password requirement: defaults write com.apple.screensaver askForPassword -int 1" \
    "Level 1"

# 5.10 Require an administrator password to access system-wide preferences
check_security_item \
    "5.10.1 Require admin password for system preferences" \
    "security authorizationdb read system.preferences 2>/dev/null | grep -A1 shared | grep -c false" \
    "1" \
    "Require admin password: security authorizationdb write system.preferences shared false" \
    "Level 1"

# 5.11 Disable ability to login to another user's active and locked session
check_security_item \
    "5.11.1 Disable fast user switching" \
    "defaults read /Library/Preferences/.GlobalPreferences MultipleSessionEnabled" \
    "0" \
    "Disable fast user switching: sudo defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false" \
    "Level 2"

# 5.12 Create a custom message for the Login Screen
check_security_item \
    "5.12.1 Set login window text" \
    "defaults read /Library/Preferences/com.apple.loginwindow LoginwindowText 2>&1 | grep -vc 'does not exist'" \
    "1" \
    "Set login message: sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText 'Authorized Use Only'" \
    "Level 1"

# 5.13 Ensure all user accounts are password protected
check_security_item \
    "5.13.1 Check for empty passwords" \
    "dscl . list /Users Password | grep -c '^*'" \
    "0" \
    "Ensure all accounts have passwords set" \
    "Level 1"

# 6. User Accounts and Environment
print_section "6. User Accounts and Environment"

# 6.1 Accounts Preferences Action Items
check_security_item \
    "6.1.1 Display login window as name and password" \
    "defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME" \
    "1" \
    "Show login window as name and password: sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true" \
    "Level 1"

check_security_item \
    "6.1.2 Disable \"Show password hints\"" \
    "defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint" \
    "0" \
    "Disable password hints: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0" \
    "Level 1"

check_security_item \
    "6.1.3 Disable guest account" \
    "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled" \
    "0" \
    "Disable guest account: sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false" \
    "Level 1"

check_security_item \
    "6.1.4 Disable \"Allow guests to connect to shared folders\"" \
    "defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess" \
    "0" \
    "Disable guest folder sharing: sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false" \
    "Level 1"

# 6.2 Turn on filename extensions
check_security_item \
    "6.2.1 Enable filename extensions" \
    "defaults read NSGlobalDomain AppleShowAllExtensions" \
    "1" \
    "Show all file extensions: defaults write NSGlobalDomain AppleShowAllExtensions -bool true" \
    "Level 1"

# 6.3 Disable the automatic run of safe files in Safari
check_security_item \
    "6.3.1 Disable Safari safe files auto-run" \
    "defaults read com.apple.Safari AutoOpenSafeDownloads" \
    "0" \
    "Disable auto-run of safe files: defaults write com.apple.Safari AutoOpenSafeDownloads -bool false" \
    "Level 1"

# 6.4 Safari disable Internet Plugins for global use
check_security_item \
    "6.4.1 Disable Safari plugins" \
    "defaults read com.apple.Safari WebKitPluginsEnabled" \
    "0" \
    "Disable Safari plugins: defaults write com.apple.Safari WebKitPluginsEnabled -bool false" \
    "Level 1"

# 6.5 Use parental controls for systems that are not centrally managed
check_security_item \
    "6.5.1 Enable parental controls where needed" \
    "profiles -P | grep -c 'There are no configuration profiles installed'" \
    "0" \
    "Consider enabling parental controls for unmanaged systems" \
    "Level 2"

# 6.6 Review System Integrity Protection status
check_security_item \
    "6.6.1 Ensure System Integrity Protection is enabled" \
    "csrutil status | grep -c 'enabled'" \
    "1" \
    "Enable System Integrity Protection: Boot to Recovery OS and run 'csrutil enable'" \
    "Level 1"

check_security_item \
    "6.7.1 Ensure Sealed System Volume is enabled" \
    "csrutil authenticated-root status | grep -c 'enabled'" \
    "1" \
    "Enable Sealed System Volume: Boot to Recovery OS and run 'csrutil authenticated-root enable'" \
    "Level 1"

# 6.8 Review permissions for home directories
check_security_item \
    "6.8.1 Ensure home directories are secure" \
    "find /Users -type d -maxdepth 1 -mindepth 1 -exec ls -ld {} \; | grep -vc '^drwx------'" \
    "0" \
    "Secure home directories: sudo chmod 700 /Users/*" \
    "Level 1"

# 6.9 Check Library folder permissions
check_security_item \
    "6.9.1 Check Library folder permissions" \
    "ls -ld /Library | grep -c '^drwxr-xr-r--'" \
    "1" \
    "Set Library permissions: sudo chmod 755 /Library" \
    "Level 1"

# 6.10 Check for world writable files
#check_security_item \
#    "6.10.1 Find world writable files" \
#    "find / -type f -perm -2 -ls 2>/dev/null | grep -vc '^$'" \
#    "0" \
#    "Remove world writable permissions where not needed" \
#    "Level 1"

# 6.11 Check for world writable directories
#check_security_item \
#    "6.11.1 Find world writable directories" \
#    "find / -type d -perm -2 -ls 2>/dev/null | grep -v '^\s*$' | grep -vc '^/tmp\|^/private/tmp\|^/private/var/tmp'" \
#    "0" \
#    "Remove world writable permissions from directories where not needed" \
#    "Level 1"

# 7. File System Configuration
print_section "7. File System Configuration"

# 7.1 Enable FileVault
check_security_item \
    "7.1.1 Enable FileVault" \
    "fdesetup status | grep -c 'FileVault is On'" \
    "1" \
    "Enable FileVault: sudo fdesetup enable" \
    "Level 1"

check_security_item \
    "7.1.2 Ensure all user storage APFS volumes are encrypted" \
    "diskutil list | grep -c 'Not Encrypted'" \
    "0" \
    "Encrypt all APFS volumes: Use Disk Utility to encrypt volumes" \
    "Level 1"

# 7.2 Enable Gatekeeper
check_security_item \
    "7.2.1 Enable Gatekeeper" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable Gatekeeper: sudo spctl --master-enable" \
    "Level 1"

check_security_item \
    "7.2.2 Enable Quarantine for downloaded applications" \
    "defaults read com.apple.LaunchServices LSQuarantine" \
    "1" \
    "Enable Quarantine: defaults write com.apple.LaunchServices LSQuarantine -bool true" \
    "Level 1"

# 7.3 Enable Library Validation
check_security_item \
    "7.3.1 Enable Library Validation" \
    "defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist Enabled" \
    "1" \
    "Enable Library Validation: sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist Enabled -bool true" \
    "Level 1"

# 7.4 Enable Secure Keyboard Entry in terminal.app
check_security_item \
    "7.4.1 Enable Secure Keyboard Entry in terminal.app" \
    "defaults read -app Terminal SecureKeyboardEntry" \
    "1" \
    "Enable Secure Keyboard Entry: defaults write -app Terminal SecureKeyboardEntry -bool true" \
    "Level 1"

# 7.5 Configure Secure Empty Trash
check_security_item \
    "7.5.1 Enable Secure Empty Trash" \
    "defaults read com.apple.finder EmptyTrashSecurely" \
    "1" \
    "Enable Secure Empty Trash: defaults write com.apple.finder EmptyTrashSecurely -bool true" \
    "Level 2"

# 7.6 Disable the automatic run of safe files in Safari
check_security_item \
    "7.6.1 Disable the automatic run of safe files in Safari" \
    "defaults read com.apple.Safari AutoOpenSafeDownloads" \
    "0" \
    "Disable automatic run of safe files: defaults write com.apple.Safari AutoOpenSafeDownloads -bool false" \
    "Level 1"

# 7.7 Disable saving passwords in Safari
check_security_item \
    "7.7.1 Disable saving passwords in Safari" \
    "defaults read com.apple.Safari AutoFillPasswords" \
    "0" \
    "Disable password saving in Safari: defaults write com.apple.Safari AutoFillPasswords -bool false" \
    "Level 1"

# 7.8 Ensure EFI version is valid and being regularly checked
check_security_item \
    "7.8.1 Ensure EFI version is valid" \
    "/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | grep -c 'No changes detected'" \
    "1" \
    "Check and update EFI firmware if needed" \
    "Level 1"

# 7.9 Ensure AirDrop is disabled
check_security_item \
    "7.9.1 Disable AirDrop" \
    "defaults read com.apple.NetworkBrowser DisableAirDrop" \
    "1" \
    "Disable AirDrop: defaults write com.apple.NetworkBrowser DisableAirDrop -bool true" \
    "Level 1"

# 7.10 Ensure File Sharing is disabled
check_security_item \
    "7.10.1 Disable File Sharing (AFP)" \
    "launchctl print-disabled system/com.apple.AppleFileServer | grep -c 'disabled => true'" \
    "1" \
    "Disable AFP: sudo launchctl disable system/com.apple.AppleFileServer" \
    "Level 1"

check_security_item \
    "7.10.2 Disable File Sharing (SMB)" \
    "launchctl print-disabled system/com.apple.smbd | grep -c 'disabled => true'" \
    "1" \
    "Disable SMB: sudo launchctl disable system/com.apple.smbd" \
    "Level 1"

# 7.11 Ensure appropriate permissions are enabled for System Security Assessment Policy
check_security_item \
    "7.11.1 Ensure security assessment policy is configured correctly" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable security assessment: sudo spctl --master-enable" \
    "Level 1"

# 7.12 Ensure Sealed System Volume (SSV) is Enabled
check_security_item \
    "7.12.1 Enable Sealed System Volume" \
    "csrutil authenticated-root status | grep -c 'enabled'" \
    "1" \
    "Enable SSV: Boot to Recovery OS and run 'csrutil authenticated-root enable'" \
    "Level 1"

# 8. Application Installation and Execution
print_section "8. Application Installation and Execution"

# 8.1 Gatekeeper and XProtect
check_security_item \
    "8.1.1 Enable Gatekeeper" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable Gatekeeper: sudo spctl --master-enable" \
    "Level 1"

check_security_item \
    "8.1.2 Enable Quarantine for downloaded applications" \
    "defaults read com.apple.LaunchServices LSQuarantine" \
    "1" \
    "Enable Quarantine: defaults write com.apple.LaunchServices LSQuarantine -bool true" \
    "Level 1"

check_security_item \
    "8.1.3 Enable XProtect" \
    "defaults read /Library/Preferences/com.apple.security.XProtect Enabled" \
    "1" \
    "Enable XProtect: sudo defaults write /Library/Preferences/com.apple.security.XProtect Enabled -bool true" \
    "Level 1"

# 8.2 Application Firewall
check_security_item \
    "8.2.1 Enable Application Firewall" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -c 'enabled'" \
    "1" \
    "Enable Application Firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" \
    "Level 1"

check_security_item \
    "8.2.2 Enable Stealth Mode" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -c 'enabled'" \
    "1" \
    "Enable Stealth Mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" \
    "Level 1"

# 8.3 Privacy Settings
check_security_item \
    "8.3.1 Review Privacy Settings for each application" \
    "tccutil list | grep -vc '^No'" \
    "1" \
    "Review and adjust Privacy Settings in System Preferences" \
    "Level 2"

# 8.4 Software Updates
check_security_item \
    "8.4.1 Enable automatic software updates" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled" \
    "1" \
    "Enable automatic updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true" \
    "Level 1"

check_security_item \
    "8.4.2 Enable app update installs" \
    "defaults read /Library/Preferences/com.apple.commerce AutoUpdate" \
    "1" \
    "Enable app updates: sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true" \
    "Level 1"

# 8.5 Malware Protection
check_security_item \
    "8.5.1 Enable XProtect Updater" \
    "defaults read /Library/Preferences/com.apple.security.XProtect AutoUpdate" \
    "1" \
    "Enable XProtect updates: sudo defaults write /Library/Preferences/com.apple.security.XProtect AutoUpdate -bool true" \
    "Level 1"

check_security_item \
    "8.5.2 Enable MRT Updater" \
    "defaults read /Library/Preferences/com.apple.security.MRT AutoUpdate" \
    "1" \
    "Enable MRT updates: sudo defaults write /Library/Preferences/com.apple.security.MRT AutoUpdate -bool true" \
    "Level 1"

# 8.6 Developer Tools
check_security_item \
    "8.6.1 Restrict developer tools access" \
    "DevToolsSecurity -status | grep -c 'enabled'" \
    "1" \
    "Restrict developer tools: sudo /usr/sbin/DevToolsSecurity -enable" \
    "Level 2"

# 8.7 App Store Settings
check_security_item \
    "8.7.1 Enable app download restrictions" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable app restrictions: sudo spctl --master-enable" \
    "Level 1"

check_security_item \
    "8.7.2 Automatically install macOS updates" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates" \
    "1" \
    "Enable macOS auto-updates: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true" \
    "Level 1"

# 9. Security & Privacy
print_section "9. Security & Privacy"

# 9.1 FileVault
check_security_item \
    "9.1.1 Enable FileVault" \
    "fdesetup status | grep -c 'FileVault is On'" \
    "1" \
    "Enable FileVault: sudo fdesetup enable" \
    "Level 1"

check_security_item \
    "9.1.2 Ensure all user storage APFS volumes are encrypted" \
    "diskutil list | grep -c 'Not Encrypted'" \
    "0" \
    "Encrypt all APFS volumes: Use Disk Utility to encrypt volumes" \
    "Level 1"

# 9.2 Firewall
check_security_item \
    "9.2.1 Enable Firewall" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -c 'enabled'" \
    "1" \
    "Enable Firewall: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on" \
    "Level 1"

check_security_item \
    "9.2.2 Enable Firewall Stealth Mode" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -c 'enabled'" \
    "1" \
    "Enable Stealth Mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on" \
    "Level 1"

check_security_item \
    "9.2.3 Review Application Firewall Rules" \
    "/usr/libexec/ApplicationFirewall/socketfilterfw --listapps | grep -c 'ALLOW'" \
    "1" \
    "Review and adjust firewall rules as needed" \
    "Level 1"

# 9.3 Privacy
check_security_item \
    "9.3.1 Enable Location Services" \
    "defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled" \
    "1" \
    "Enable Location Services in System Preferences > Security & Privacy > Privacy" \
    "Level 2"

check_security_item \
    "9.3.2 Review Location Services Access" \
    "defaults read /var/db/locationd/clients.plist | grep -c 'Authorized'" \
    "1" \
    "Review Location Services access for applications" \
    "Level 2"

check_security_item \
    "9.3.3 Review Accessibility API access" \
    "tccutil list | grep -c 'kTCCServiceAccessibility'" \
    "1" \
    "Review Accessibility access in System Preferences > Security & Privacy > Privacy" \
    "Level 1"

# 9.4 Privacy - Camera and Microphone
check_security_item \
    "9.4.1 Review Camera access" \
    "tccutil list | grep -c 'kTCCServiceCamera'" \
    "1" \
    "Review Camera access in System Preferences > Security & Privacy > Privacy" \
    "Level 1"

check_security_item \
    "9.4.2 Review Microphone access" \
    "tccutil list | grep -c 'kTCCServiceMicrophone'" \
    "1" \
    "Review Microphone access in System Preferences > Security & Privacy > Privacy" \
    "Level 1"

# 9.5 Privacy - Analytics
check_security_item \
    "9.5.1 Disable sending diagnostic and usage data to Apple" \
    "defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit" \
    "0" \
    "Disable diagnostic data submission: sudo defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false" \
    "Level 2"

# 9.6 Bluetooth Security
check_security_item \
    "9.6.1 Disable Bluetooth if not needed" \
    "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState" \
    "0" \
    "Disable Bluetooth: sudo defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0" \
    "Level 2"

check_security_item \
    "9.6.2 Disable Bluetooth Sharing" \
    "defaults read /Library/Preferences/com.apple.Bluetooth PrefKeyServicesEnabled" \
    "0" \
    "Disable Bluetooth Sharing: sudo defaults write /Library/Preferences/com.apple.Bluetooth PrefKeyServicesEnabled -bool false" \
    "Level 1"

# 9.7 iCloud Configuration
check_security_item \
    "9.7.1 iCloud keychain" \
    "security list-keychains | grep -c 'iCloud'" \
    "1" \
    "Review iCloud keychain settings" \
    "Level 2"

check_security_item \
    "9.7.2 iCloud Drive" \
    "defaults read com.apple.iCloud | grep -c 'NSNumber.*9'" \
    "0" \
    "Review iCloud Drive settings and disable if not needed" \
    "Level 2"

# 9.8 Screen Sharing & Remote Management
check_security_item \
    "9.8.1 Disable Screen Sharing" \
    "launchctl print-disabled system/com.apple.screensharing | grep -c 'disabled => true'" \
    "1" \
    "Disable Screen Sharing: sudo launchctl disable system/com.apple.screensharing" \
    "Level 1"

check_security_item \
    "9.8.2 Disable Remote Management" \
    "ps aux | grep -c '[A]RDAgent'" \
    "0" \
    "Disable Remote Management: sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop" \
    "Level 1"

# 10. iCloud Configuration
print_section "10. iCloud Configuration"

# 10.1 iCloud Account Settings
check_security_item \
    "10.1.1 Review iCloud account configuration" \
    "defaults read MobileMeAccounts Accounts 2>/dev/null | grep -c 'AccountID'" \
    "1" \
    "Review iCloud account settings in System Preferences" \
    "Level 2"

# 10.2 iCloud Keychain
check_security_item \
    "10.2.1 Review iCloud Keychain status" \
    "security list-keychains | grep -c 'iCloud'" \
    "1" \
    "Review iCloud Keychain settings" \
    "Level 2"

check_security_item \
    "10.2.2 Enable two-factor authentication for Apple ID" \
    "defaults read com.apple.MobileMe TwoFactorAuthentication" \
    "1" \
    "Enable two-factor authentication for Apple ID" \
    "Level 1"

# 10.3 iCloud Drive
check_security_item \
    "10.3.1 Review iCloud Drive settings" \
    "defaults read com.apple.iCloud | grep -c 'PrimaryServices.*NSNumber.*9'" \
    "0" \
    "Review and configure iCloud Drive settings" \
    "Level 2"

check_security_item \
    "10.3.2 Disable iCloud Desktop & Documents" \
    "defaults read com.apple.iCloud | grep -c 'NSNumber.*2'" \
    "0" \
    "Disable iCloud Desktop & Documents syncing if not needed" \
    "Level 2"

# 10.4 iCloud Photos
check_security_item \
    "10.4.1 Review iCloud Photos settings" \
    "defaults read com.apple.iCloud | grep -c 'NSNumber.*5'" \
    "0" \
    "Review and configure iCloud Photos settings" \
    "Level 2"

# 10.5 iCloud Backup
check_security_item \
    "10.5.1 Review iCloud Backup settings" \
    "defaults read com.apple.iCloud | grep -c 'NSNumber.*3'" \
    "0" \
    "Review and configure iCloud Backup settings" \
    "Level 2"

# 10.6 Find My Mac
check_security_item \
    "10.6.1 Enable Find My Mac" \
    "defaults read com.apple.FindMyMac FMMEnabled" \
    "1" \
    "Enable Find My Mac in iCloud settings" \
    "Level 1"

# 10.7 iCloud Mail
check_security_item \
    "10.7.1 Review iCloud Mail settings" \
    "defaults read com.apple.mail-shared | grep -c 'EnabledAccounts.*iCloud'" \
    "0" \
    "Review and configure iCloud Mail settings if needed" \
    "Level 2"

# 10.8 iCloud Sharing
check_security_item \
    "10.8.1 Review iCloud sharing settings" \
    "defaults read com.apple.iCloud | grep -c 'NSNumber.*7'" \
    "0" \
    "Review and configure iCloud sharing settings" \
    "Level 2"

# 10.9 iCloud Private Relay
check_security_item \
    "10.9.1 Enable iCloud Private Relay" \
    "defaults read com.apple.iCloud | grep -c 'PrivateRelayEnabled.*1'" \
    "1" \
    "Enable iCloud Private Relay for enhanced privacy" \
    "Level 2"

# 10.10 iCloud Security Recommendations
check_security_item \
    "10.10.1 Review Security Recommendations" \
    "defaults read com.apple.iCloud | grep -c 'SecurityUpgradeState.*1'" \
    "1" \
    "Review and implement iCloud security recommendations" \
    "Level 1"

# 11. Privacy Settings
print_section "11. Privacy Settings"

# 11.1 Location Services
check_security_item \
    "11.1.1 Review Location Services" \
    "defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled" \
    "1" \
    "Review Location Services settings" \
    "Level 2"

check_security_item \
    "11.1.2 Review Location Services System Services" \
    "defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd SystemServices" \
    "1" \
    "Review System Services Location access" \
    "Level 2"

# 11.2 Contacts
check_security_item \
    "11.2.1 Review Contacts Access" \
    "tccutil list | grep -c 'kTCCServiceAddressBook'" \
    "1" \
    "Review application access to Contacts" \
    "Level 1"

# 11.3 Calendars
check_security_item \
    "11.3.1 Review Calendar Access" \
    "tccutil list | grep -c 'kTCCServiceCalendar'" \
    "1" \
    "Review application access to Calendars" \
    "Level 1"

# 11.4 Reminders
check_security_item \
    "11.4.1 Review Reminders Access" \
    "tccutil list | grep -c 'kTCCServiceReminders'" \
    "1" \
    "Review application access to Reminders" \
    "Level 1"

# 11.5 Photos
check_security_item \
    "11.5.1 Review Photos Access" \
    "tccutil list | grep -c 'kTCCServicePhotos'" \
    "1" \
    "Review application access to Photos" \
    "Level 1"

# 11.6 Camera
check_security_item \
    "11.6.1 Review Camera Access" \
    "tccutil list | grep -c 'kTCCServiceCamera'" \
    "1" \
    "Review application access to Camera" \
    "Level 1"

# 11.7 Microphone
check_security_item \
    "11.7.1 Review Microphone Access" \
    "tccutil list | grep -c 'kTCCServiceMicrophone'" \
    "1" \
    "Review application access to Microphone" \
    "Level 1"

# 11.8 Accessibility
check_security_item \
    "11.8.1 Review Accessibility Access" \
    "tccutil list | grep -c 'kTCCServiceAccessibility'" \
    "1" \
    "Review application access to Accessibility" \
    "Level 1"

# 11.9 Full Disk Access
check_security_item \
    "11.9.1 Review Full Disk Access" \
    "tccutil list | grep -c 'kTCCServiceSystemPolicyAllFiles'" \
    "1" \
    "Review application access to Full Disk Access" \
    "Level 1"

# 11.10 Analytics
check_security_item \
    "11.10.1 Disable Analytics Data Submission" \
    "defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit" \
    "0" \
    "Disable Analytics Data Submission" \
    "Level 2"

check_security_item \
    "11.10.2 Disable Siri Analytics" \
    "defaults read com.apple.assistant.support 'Siri Data Sharing Opt-In Status'" \
    "0" \
    "Disable Siri Analytics sharing" \
    "Level 2"

# 11.11 Advertising
check_security_item \
    "11.11.1 Enable Limit Ad Tracking" \
    "defaults read com.apple.AdLib forceLimitAdTracking" \
    "1" \
    "Enable Limit Ad Tracking" \
    "Level 2"

# 12. System Hardening
print_section "12. System Hardening"

# 12.1 Core Dumps
check_security_item \
    "12.1.1 Disable Core Dumps" \
    "sysctl kern.coredump | awk '{print \$2}'" \
    "0" \
    "Disable core dumps: sudo sysctl -w kern.coredump=0" \
    "Level 1"

# 12.2 Hibernate Mode
check_security_item \
    "12.2.1 Enable Hibernate Mode" \
    "pmset -g | grep -c 'hibernatemode.*25'" \
    "1" \
    "Enable hibernate mode: sudo pmset -a hibernatemode 25" \
    "Level 2"

# 12.3 Power Management
check_security_item \
    "12.3.1 Disable wake on network access" \
    "pmset -g | grep -c 'womp.*0'" \
    "1" \
    "Disable wake on network: sudo pmset -a womp 0" \
    "Level 2"

check_security_item \
    "12.3.2 Disable Power Nap" \
    "pmset -g | grep -c 'powernap.*0'" \
    "1" \
    "Disable Power Nap: sudo pmset -a powernap 0" \
    "Level 2"

# 12.4 Time Machine
check_security_item \
    "12.4.1 Enable Time Machine" \
    "defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup" \
    "1" \
    "Enable Time Machine backups" \
    "Level 1"

check_security_item \
    "12.4.2 Enable Time Machine encryption" \
    "defaults read /Library/Preferences/com.apple.TimeMachine RequiresEncryption" \
    "1" \
    "Enable Time Machine encryption" \
    "Level 1"

# 12.5 Firmware Password
check_security_item \
    "12.5.1 Enable firmware password" \
    "sudo firmwarepasswd -check | grep -c 'Password Enabled: Yes'" \
    "1" \
    "Enable firmware password protection" \
    "Level 2"

# 12.6 Secure Boot
check_security_item \
    "12.6.1 Enable Secure Boot" \
    "system_profiler SPiBridgeDataType | grep -c 'Secure Boot: Full Security'" \
    "1" \
    "Enable Secure Boot in Recovery Mode" \
    "Level 1"

# 12.7 System Integrity Protection
check_security_item \
    "12.7.1 Enable System Integrity Protection" \
    "csrutil status | grep -c 'enabled'" \
    "1" \
    "Enable System Integrity Protection in Recovery Mode" \
    "Level 1"

# 12.8 FileVault
check_security_item \
    "12.8.1 Enable FileVault" \
    "fdesetup status | grep -c 'FileVault is On'" \
    "1" \
    "Enable FileVault disk encryption" \
    "Level 1"

# 12.9 Gatekeeper
check_security_item \
    "12.9.1 Enable Gatekeeper" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable Gatekeeper: sudo spctl --master-enable" \
    "Level 1"

# 12.10 Automatic Terminal Logout
check_security_item \
    "12.10.1 Set shell timeout" \
    "grep -c '^TMOUT=' /etc/profile" \
    "1" \
    "Set shell timeout: echo 'TMOUT=900' >> /etc/profile" \
    "Level 2"

# 12.11 Secure Keyboard Entry
check_security_item \
    "12.11.1 Enable Secure Keyboard Entry in Terminal" \
    "defaults read -app Terminal SecureKeyboardEntry" \
    "1" \
    "Enable Secure Keyboard Entry in Terminal" \
    "Level 1"

# 12.12 Screen Lock
check_security_item \
    "12.12.1 Set screen saver timeout" \
    "defaults read com.apple.screensaver idleTime 2>/dev/null | awk '{exit ($1 > 1200)}'" \
    "0" \
    "Set screen saver timeout to 20 minutes or less" \
    "Level 1"

# 12.13 Sharing
check_security_item \
    "12.13.1 Disable Remote Apple Events" \
    "systemsetup -getremoteappleevents | grep -c 'Remote Apple Events: Off'" \
    "1" \
    "Disable Remote Apple Events" \
    "Level 1"

check_security_item \
    "12.13.2 Disable Internet Sharing" \
    "defaults read /Library/Preferences/SystemConfiguration/com.apple.nat | grep -c 'Enabled = 1'" \
    "0" \
    "Disable Internet Sharing" \
    "Level 1"

# 13. Software Updates
print_section "13. Software Updates"

# 13.1 App Store Updates
check_security_item \
    "13.1.1 Enable automatic app updates" \
    "defaults read /Library/Preferences/com.apple.commerce AutoUpdate" \
    "1" \
    "Enable automatic app updates" \
    "Level 1"

check_security_item \
    "13.1.2 Enable system data files installation" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall" \
    "1" \
    "Enable system data files installation" \
    "Level 1"

check_security_item \
    "13.1.3 Enable security updates installation" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall" \
    "1" \
    "Enable security updates installation" \
    "Level 1"

# 13.2 System Updates
check_security_item \
    "13.2.1 Enable automatic checking for updates" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled" \
    "1" \
    "Enable automatic update checks" \
    "Level 1"

check_security_item \
    "13.2.2 Enable automatic download of updates" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload" \
    "1" \
    "Enable automatic update downloads" \
    "Level 1"

# 13.3 XProtect and MRT
check_security_item \
    "13.3.1 Enable XProtect updates" \
    "defaults read /Library/Preferences/com.apple.security.XProtect AutoUpdate" \
    "1" \
    "Enable XProtect updates" \
    "Level 1"

check_security_item \
    "13.3.2 Enable MRT updates" \
    "defaults read /Library/Preferences/com.apple.security.MRT AutoUpdate" \
    "1" \
    "Enable MRT updates" \
    "Level 1"

# 13.4 Certificate Updates
check_security_item \
    "13.4.1 Enable certificate updates" \
    "defaults read /Library/Preferences/com.apple.security.revocation AutoUpdate" \
    "1" \
    "Enable certificate updates" \
    "Level 1"

# 13.5 Software Update History
check_security_item \
    "13.5.1 Verify recent updates" \
    "softwareupdate --history | grep -c 'Install Date: Last 30 days'" \
    "1" \
    "Check and install pending updates" \
    "Level 2"

# 13.6 Gatekeeper Updates
check_security_item \
    "13.6.1 Enable Gatekeeper updates" \
    "spctl --status | grep -c 'assessments enabled'" \
    "1" \
    "Enable Gatekeeper and its updates" \
    "Level 1"

# 13.7 Developer Tools
check_security_item \
    "13.7.1 Update developer tools" \
    "xcode-select -p >/dev/null 2>&1 && softwareupdate --history | grep -c 'Command Line Tools'" \
    "1" \
    "Update developer tools if installed" \
    "Level 2"

# 14. Security Audit
print_section "14. Security Audit"

# 14.1 Audit Logs
check_security_item \
    "14.1.1 Enable security auditing" \
    "launchctl list | grep -c 'com.apple.auditd'" \
    "1" \
    "Enable security auditing" \
    "Level 1"

check_security_item \
    "14.1.2 Configure audit log retention" \
    "grep -c 'expire-after:60d OR 5G' /etc/security/audit_control" \
    "1" \
    "Configure audit log retention" \
    "Level 2"

# 14.2 Audit Flags
check_security_item \
    "14.2.1 Enable audit flags for login/logout" \
    "grep -c 'flags:lo' /etc/security/audit_control" \
    "1" \
    "Enable login/logout auditing" \
    "Level 1"

check_security_item \
    "14.2.2 Enable audit flags for administrative actions" \
    "grep -c 'flags:ad' /etc/security/audit_control" \
    "1" \
    "Enable administrative actions auditing" \
    "Level 1"

# 14.3 System Integrity
check_security_item \
    "14.3.1 Verify system integrity" \
    "sudo /usr/libexec/check_system_integrity.sh >/dev/null 2>&1; echo \$?" \
    "0" \
    "Verify system integrity" \
    "Level 1"

# 14.4 File Integrity
check_security_item \
    "14.4.1 Enable file integrity monitoring" \
    "sudo /usr/local/bin/osquery --config_path=/etc/osquery/osquery.conf --config_check >/dev/null 2>&1; echo \$?" \
    "0" \
    "Install and configure file integrity monitoring" \
    "Level 2"

# 14.5 Log Files
check_security_item \
    "14.5.1 Verify log files permissions" \
    "find /var/log -type f -perm -o+w -ls | wc -l" \
    "0" \
    "Secure log files permissions" \
    "Level 1"

check_security_item \
    "14.5.2 Enable system.log" \
    "grep -c '^> system.log' /etc/syslog.conf" \
    "1" \
    "Enable system logging" \
    "Level 1"

# 14.6 Security Events
check_security_item \
    "14.6.1 Monitor security events" \
    "launchctl list | grep -c 'com.apple.securityd'" \
    "1" \
    "Enable security event monitoring" \
    "Level 1"

# 14.7 Audit Configuration
check_security_item \
    "14.7.1 Protect audit configuration" \
    "stat -f '%Op' /etc/security/audit_control | grep -c '440'" \
    "1" \
    "Secure audit configuration files" \
    "Level 1"

# 14.8 Remote Logging
check_security_item \
    "14.8.1 Configure remote logging" \
    "grep -c '^@' /etc/syslog.conf" \
    "1" \
    "Configure remote logging if required" \
    "Level 2"

# 15. Additional Security Controls
print_section "15. Additional Security Controls"

# 15.1 Endpoint Security
check_security_item \
    "15.1.1 Verify endpoint protection" \
    "system_profiler SPConfigurationProfileDataType | grep -c 'EndpointSecurity'" \
    "1" \
    "Install and configure endpoint security software" \
    "Level 1"

# 15.2 Data Loss Prevention
check_security_item \
    "15.2.1 Enable data loss prevention" \
    "system_profiler SPConfigurationProfileDataType | grep -c 'DataLossPrevention'" \
    "1" \
    "Configure data loss prevention policies" \
    "Level 2"

# 15.3 Security Training
check_security_item \
    "15.3.1 Verify security awareness" \
    "test -f /Library/Security/SecurityAwareness.txt && grep -c 'LastTrainingDate' /Library/Security/SecurityAwareness.txt" \
    "1" \
    "Ensure security awareness training is completed and documented" \
    "Level 2"

# Generate Report
print_section "Security Check Report"

# Print summary to console
echo ""
echo "Security Check Report Summary"
echo "============================"
echo "Total Checks Run: $total_checks"
echo "CIS MacOS Security Benchmark v4.0.0 - $(date)"
echo "Sections Covered: 15"
echo "Level 1 (Required) Checks: $level1_checks"
echo "Level 2 (Recommended) Checks: $level2_checks"
echo "Passed Checks: $passed_checks"
echo "Failed Checks: $failed_checks"
if [ "$total_checks" -gt 0 ]; then
    echo "Compliance Rate: $(( (passed_checks * 100) / total_checks ))%"
else
    echo "Compliance Rate: N/A (no checks run)"
fi
echo ""
echo "Detailed report saved to: $report_file"
echo "To view the report, run: cat $report_file"
echo ""
echo "Run this script with sudo privileges to perform all checks:"
echo "sudo bash $(basename "$0")"

print_detailed_report() {
    local report_file="$1"
    
    {
        echo "CIS macOS Security Benchmark v4.0.0 - $(date)"
        echo "=================================================="
        echo ""
        
        # Executive Summary
        echo "EXECUTIVE SUMMARY"
        echo "================"
        echo "Total Checks Run: $total_checks"
        echo "Sections Covered: 15"
        echo "Level 1 (Required) Checks: $level1_checks"
        echo "Level 2 (Recommended) Checks: $level2_checks"
        echo "Passed Checks: $passed_checks"
        echo "Failed Checks: $failed_checks"
        if [ "$total_checks" -gt 0 ]; then
            echo "Compliance Rate: $(( (passed_checks * 100) / total_checks ))%"
        else
            echo "Compliance Rate: N/A (no checks run)"
        fi
        echo ""
        
        # Detailed Results by Section
        echo "DETAILED RESULTS BY SECTION"
        echo "=========================="
        echo ""
        
        current_section=""
        section_pass_count=0
        section_total_count=0
        
        for i in "${!check_names[@]}"; do
            # Extract section name from check name
            section=$(echo "${check_names[$i]}" | cut -d. -f1)
            
            # If we're starting a new section, print the previous section's summary
            if [ "$section" != "$current_section" ]; then
                if [ -n "$current_section" ]; then
                    echo "Section $current_section Summary:"
                    echo "Compliance Rate: $(( (section_pass_count * 100) / section_total_count ))%"
                    echo "($section_pass_count of $section_total_count checks passed)"
                    echo "----------------------------------------"
                    echo ""
                fi
                
                # Reset counters for new section
                section_pass_count=0
                section_total_count=0
                current_section="$section"
                
                echo "Section $section"
                echo "-------------"
            fi
            
            # Update section counters
            ((section_total_count++))
            [ "${check_results[$i]}" = "Pass" ] && ((section_pass_count++))
            
            # Print check details
            printf "%-4s %-60s [%s]\n" "$section" "${check_names[$i]}" "${check_results[$i]}"
            echo "Level: ${check_levels[$i]}"
            if [ "${check_results[$i]}" = "Fail" ]; then
                echo "Remediation: ${check_remediations[$i]}"
            fi
            echo "----------------------------------------"
        done
        
        # Print last section's summary
        if [ -n "$current_section" ]; then
            echo "Section $current_section Summary:"
            echo "Compliance Rate: $(( (section_pass_count * 100) / section_total_count ))%"
            echo "($section_pass_count of $section_total_count checks passed)"
            echo "----------------------------------------"
            echo ""
        fi
        
        # Critical Findings (Level 1 Failures)
        echo "CRITICAL FINDINGS (Level 1)"
        echo "=========================="
        echo "The following required security controls have failed and should be addressed immediately:"
        echo ""
        for i in "${!check_names[@]}"; do
            if [ "${check_levels[$i]}" = "Level 1" ] && [ "${check_results[$i]}" = "Fail" ]; then
                echo "❌ ${check_names[$i]}"
                echo "   Remediation: ${check_remediations[$i]}"
                echo ""
            fi
        done
        
        # Recommendations (Level 2 Failures)
        echo "RECOMMENDATIONS (Level 2)"
        echo "======================="
        echo "The following recommended security controls should be considered for implementation:"
        echo ""
        for i in "${!check_names[@]}"; do
            if [ "${check_levels[$i]}" = "Level 2" ] && [ "${check_results[$i]}" = "Fail" ]; then
                echo "⚠️  ${check_names[$i]}"
                echo "   Remediation: ${check_remediations[$i]}"
                echo ""
            fi
        done
        
        # Report Footer
        echo "REPORT INFORMATION"
        echo "================="
        echo "Generated on: $(date)"
        echo "Benchmark Version: CIS macOS Security Benchmark v4.0.0"
        echo "Script Version: 1.0.0"
        echo "Privilege Level: $([ "$EUID" -eq 0 ] && echo "Root/Administrative" || echo "Standard User")"
        echo ""
        echo "Note: Some checks require administrative privileges to run properly."
        echo "For most accurate results, run this script with sudo privileges."
    } > "$report_file"
}

# Clean up temporary files
rm -f system_info.txt
