# CyberSecurityPilot.org

## Quick Start

### 1. DNS Security Checks
```bash
# Run DNS monitoring and checks
python3 scripts/dns_monitor.py

# Update DNS report dashboard
python3 scripts/update_dns_dashboard.py
```

### 2. CIS Security Checks
```bash
# Run CIS security checks and generate report
./scripts/cis_macos_check.sh

# Convert report to JSON and update dashboard
./scripts/report_to_json.sh

# Generate individual report dashboards
./scripts/generate_report_dashboard.sh dashboard/reports/cis_security_report_*.txt
```

### 3. View Dashboards
- DNS Security: http://localhost:8080/dashboard/dns_table.html
- CIS Security: http://localhost:8080/dashboard/cis-report-dashboard.html

## Directory Structure
```
CyberSecurityPilot.org/
├── dashboard/
│   ├── dns_table.html
│   ├── cis-report-dashboard.html
│   └── reports/
│       ├── reports_list.json
│       ├── cis_security_report_*.txt
│       ├── cis_security_report_*.json
│       └── cis_security_report_*.html
└── scripts/
    ├── dns_monitor.py
    ├── update_dns_dashboard.py
    ├── cis_macos_check.sh
    ├── report_to_json.sh
    └── generate_report_dashboard.sh
```

## Dependencies
- Python 3.8+
- Tailwind CSS (CDN)
