#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"
DASHBOARD_FILE="$SCRIPT_DIR/../dashboard/cis-report-dashboard.html"

# Check if reports directory exists
if [ ! -d "$REPORTS_DIR" ]; then
    echo "Error: Reports directory not found at $REPORTS_DIR"
    exit 1
fi

# Create dashboard if it doesn't exist
if [ ! -f "$DASHBOARD_FILE" ]; then
    cat > "$DASHBOARD_FILE" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Reports Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <div class="min-h-screen">
        <nav class="bg-white shadow">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div class="flex h-16 justify-between">
                    <div class="flex">
                        <div class="flex flex-shrink-0 items-center">
                            <h1 class="text-xl font-semibold">CIS Security Reports</h1>
                        </div>
                    </div>
                </div>
            </div>
        </nav>

        <main>
            <div class="mx-auto max-w-7xl py-6 sm:px-6 lg:px-8">
                <!-- Current Report Summary -->
                <div class="mb-8">
                    <h2 class="text-lg font-semibold mb-4">Current Report Summary</h2>
                    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        <div class="bg-white overflow-hidden shadow rounded-lg">
                            <div class="p-5">
                                <div class="flex items-center">
                                    <div class="flex-shrink-0">
                                        <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                        </svg>
                                    </div>
                                    <div class="ml-5 w-0 flex-1">
                                        <dl>
                                            <dt class="text-sm font-medium text-gray-500 truncate">Report Date</dt>
                                            <dd class="text-lg font-medium text-gray-900" id="currentReportDate">-</dd>
                                        </dl>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="bg-white overflow-hidden shadow rounded-lg">
                            <div class="p-5">
                                <div class="flex items-center">
                                    <div class="flex-shrink-0">
                                        <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                    <div class="ml-5 w-0 flex-1">
                                        <dl>
                                            <dt class="text-sm font-medium text-gray-500 truncate">Compliance Rate</dt>
                                            <dd class="text-lg font-medium text-gray-900" id="complianceRate">-</dd>
                                        </dl>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="bg-white overflow-hidden shadow rounded-lg">
                            <div class="p-5">
                                <div class="flex items-center">
                                    <div class="flex-shrink-0">
                                        <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                        </svg>
                                    </div>
                                    <div class="ml-5 w-0 flex-1">
                                        <dl>
                                            <dt class="text-sm font-medium text-gray-500 truncate">Total Checks</dt>
                                            <dd class="text-lg font-medium text-gray-900" id="totalChecks">-</dd>
                                        </dl>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="bg-white overflow-hidden shadow rounded-lg">
                            <div class="p-5">
                                <div class="flex items-center">
                                    <div class="flex-shrink-0">
                                        <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                    <div class="ml-5 w-0 flex-1">
                                        <dl>
                                            <dt class="text-sm font-medium text-gray-500 truncate">Passed/Failed</dt>
                                            <dd class="text-lg font-medium text-gray-900">
                                                <span id="passedChecks" class="text-green-600">-</span>
                                                <span class="text-gray-400">/</span>
                                                <span id="failedChecks" class="text-red-600">-</span>
                                            </dd>
                                        </dl>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Historical Reports -->
                <div>
                    <h2 class="text-lg font-semibold mb-4">Historical Reports</h2>
                    <div class="bg-white shadow overflow-hidden sm:rounded-lg">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Compliance</th>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Checks</th>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">System</th>
                                    <th scope="col" class="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200" id="reportsTableBody">
                                <!-- Reports will be inserted here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        let currentReport = null;
        let checkFilter = 'all';
        
        // Reports list will be inserted here
        const reportsList = [];

        function displayCurrentReport(report) {
            currentReport = report;
            
            // Update summary cards
            document.getElementById('currentReportDate').textContent = new Date(report.timestamp).toLocaleString();
            document.getElementById('complianceRate').textContent = `${report.summary.compliance_rate}%`;
            document.getElementById('totalChecks').textContent = report.summary.total_checks;
            document.getElementById('passedChecks').textContent = report.summary.passed_checks;
            document.getElementById('failedChecks').textContent = report.summary.failed_checks;
        }

        function displayReports() {
            const tbody = document.getElementById('reportsTableBody');
            tbody.innerHTML = '';

            if (reportsList.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" class="px-3 py-2 text-center text-sm text-gray-500">
                            No reports found. Run the CIS check script to generate reports.
                        </td>
                    </tr>
                `;
                return;
            }

            reportsList.forEach(report => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50';
                row.innerHTML = `
                    <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-900">
                        ${new Date(report.timestamp).toLocaleString()}
                    </td>
                    <td class="px-3 py-2 whitespace-nowrap">
                        <div class="flex items-center space-x-2">
                            <span class="text-sm font-medium text-gray-900">${report.summary.compliance_rate}%</span>
                            <div class="w-16 bg-gray-200 rounded-full h-1.5">
                                <div class="bg-${report.summary.compliance_rate >= 70 ? 'green' : report.summary.compliance_rate >= 40 ? 'yellow' : 'red'}-500 rounded-full h-1.5" 
                                     style="width: ${report.summary.compliance_rate}%">
                                </div>
                            </div>
                        </div>
                    </td>
                    <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-900">
                        ${report.summary.passed_checks}/${report.summary.total_checks}
                    </td>
                    <td class="px-3 py-2 whitespace-nowrap text-sm text-gray-500">
                        <div class="flex flex-col">
                            <span>${report.system_info.system_information.model}</span>
                            <span class="text-xs text-gray-400">macOS ${report.system_info.system_information.macosversion}</span>
                        </div>
                    </td>
                    <td class="px-3 py-2 whitespace-nowrap text-sm font-medium">
                        <div class="flex items-center space-x-2">
                            <button onclick='displayCurrentReport(${JSON.stringify(report)})' class="text-blue-600 hover:text-blue-900">
                                Show Details
                            </button>
                            <a href="${report.report_file}" class="text-gray-500 hover:text-gray-700" title="View Text Report" target="_blank">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                            </a>
                            <a href="${report.report_file.replace('.txt', '.json')}" class="text-gray-500 hover:text-gray-700" title="View JSON Report" target="_blank">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                                </svg>
                            </a>
                            <a href="${report.report_file}" download class="text-gray-500 hover:text-gray-700" title="Download Text Report">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                            </a>
                        </div>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        // Initialize the dashboard
        document.addEventListener('DOMContentLoaded', () => {
            displayReports();
            if (reportsList.length > 0) {
                displayCurrentReport(reportsList[0]);
            }
        });

        function filterChecks(filter) {
            checkFilter = filter;
            displayAllChecks();
        }
    </script>
</body>
</html>
EOL
    # Ensure correct permissions
    chmod 644 "$DASHBOARD_FILE"
fi

# Function to extract value from report using regex
extract_value() {
    local file="$1"
    local pattern="$2"
    grep -E "$pattern" "$file" | sed -E "s/$pattern/\1/"
}

# Create a temporary file for the new content
temp_file=$(mktemp)
chmod 644 "$temp_file"

# Get all report files sorted by date (newest first)
report_files=$(ls -t "$REPORTS_DIR"/cis_security_report_*.txt 2>/dev/null)

if [ -z "$report_files" ]; then
    echo "No report files found in $REPORTS_DIR"
    exit 1
fi

# Process each report file
echo "[" > "$REPORTS_DIR/reports_list.json"
first_entry=true

for report_file in $report_files; do
    if [ "$first_entry" = false ]; then
        echo "," >> "$REPORTS_DIR/reports_list.json"
    fi
    
    base_name=$(basename "$report_file" .txt)
    json_file="$REPORTS_DIR/${base_name}.json"
    html_file="$REPORTS_DIR/${base_name}.html"
    
    # Extract report date from filename
    date_str=$(echo "$base_name" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
    formatted_date=$(date -j -f "%Y%m%d_%H%M%S" "$date_str" "+%Y-%m-%dT%H:%M:%S")
    
    # Extract metrics
    total=$(grep "Total Checks Run:" "$report_file" | awk '{print $4}' | head -n1)
    passed=$(grep "Passed Checks:" "$report_file" | awk '{print $3}' | head -n1)
    failed=$(grep "Failed Checks:" "$report_file" | awk '{print $3}' | head -n1)
    compliance=$(grep "Compliance Rate:" "$report_file" | awk '{print $3}' | tr -d '%' | head -n1)
    
    # Extract system info
    hostname=$(hostname)
    model=$(system_profiler SPHardwareDataType | grep "Model Name" | cut -d: -f2- | xargs)
    macos_version=$(sw_vers -productVersion)
    processor=$(sysctl -n machdep.cpu.brand_string)
    memory=$(system_profiler SPHardwareDataType | grep "Memory:" | cut -d: -f2- | xargs)
    
    # Create JSON entry
    cat >> "$REPORTS_DIR/reports_list.json" << EOL
    {
      "date": "$formatted_date",
      "total": $total,
      "passed": $passed,
      "failed": $failed,
      "compliance": $compliance,
      "txt": "$(basename "$report_file")",
      "json": "$(basename "$json_file")",
      "html": "$(basename "$html_file")",
      "hostname": "$hostname",
      "model": "$model",
      "macos_version": "$macos_version",
      "processor": "$processor",
      "memory": "$memory"
    }
EOL
    first_entry=false
done

echo "]" >> "$REPORTS_DIR/reports_list.json"

echo "Generated reports list: $REPORTS_DIR/reports_list.json"
echo "Generated dashboard: $DASHBOARD_FILE"
echo "Report processing complete!"
