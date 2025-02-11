#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"
DASHBOARD_DIR="$SCRIPT_DIR/../dashboard"

# Generate reports_list.json
echo '[' > "$REPORTS_DIR/reports_list.json"

first=true
reports=($(ls -t "$REPORTS_DIR"/cis_security_report_*.txt))
prev_passed=0
prev_failed=0

# Process reports from newest to oldest
for report in "${reports[@]}"; do
    if [ -f "$report" ]; then
        # Extract timestamp from filename
        timestamp=$(echo "$report" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
        formatted_date=$(date -j -f "%Y%m%d_%H%M%S" "$timestamp" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null)
        
        # Get base filename without extension
        base=$(basename "$report" .txt)
        
        # Extract metrics from the report (using head -n1 to get only the first match)
        total=$(grep "Total Checks Run:" "$report" | awk '{print $4}' | head -n1)
        passed=$(grep "Passed Checks:" "$report" | awk '{print $3}' | head -n1)
        failed=$(grep "Failed Checks:" "$report" | awk '{print $3}' | head -n1)
        compliance=$(grep "Compliance Rate:" "$report" | awk '{print $3}' | tr -d '%' | head -n1)
        
        # Use 0 as default for missing values
        total=${total:-0}
        passed=${passed:-0}
        failed=${failed:-0}
        compliance=${compliance:-0}
        
        # Calculate deltas from previous report
        passed_delta=$((passed - prev_passed))
        failed_delta=$((failed - prev_failed))
        
        # Store current values for next iteration
        prev_passed=$passed
        prev_failed=$failed
        
        # Get system information using system_profiler
        hostname=$(hostname)
        model=$(system_profiler SPHardwareDataType | grep "Model Name" | cut -d: -f2- | xargs)
        macos_version=$(sw_vers -productVersion)
        processor=$(sysctl -n machdep.cpu.brand_string)
        memory=$(system_profiler SPHardwareDataType | grep "Memory:" | cut -d: -f2- | xargs)
        
        # Add comma if not first entry
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$REPORTS_DIR/reports_list.json"
        fi
        
        # Add report entry
        cat >> "$REPORTS_DIR/reports_list.json" << EOL
    {
      "date": "$formatted_date",
      "total": $total,
      "passed": $passed,
      "failed": $failed,
      "compliance": $compliance,
      "txt": "$(basename "$report")",
      "json": "${base}.json",
      "html": "${base}.html",
      "passed_delta": $passed_delta,
      "failed_delta": $failed_delta,
      "hostname": "$hostname",
      "model": "$model",
      "macos_version": "$macos_version",
      "processor": "$processor",
      "memory": "$memory"
    }
EOL
    fi
done

echo ']' >> "$REPORTS_DIR/reports_list.json"

# Generate main dashboard HTML header
cat > "$DASHBOARD_DIR/cis-report-dashboard.html" << 'EOL'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Reports</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-white shadow">
            <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
                <h1 class="text-3xl font-bold text-gray-900">
                    CIS Security Reports
                </h1>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <!-- Reports List -->
            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-4 sm:p-6">
                    <h2 class="text-xl font-semibold text-gray-900 mb-4">Available Reports</h2>
                    <div class="space-y-4">
EOL

# Process reports from newest to oldest
for report in "${reports[@]}"; do
    if [ -f "$report" ]; then
        timestamp=$(echo "$report" | grep -o '[0-9]\{8\}_[0-9]\{6\}')
        formatted_date=$(date -j -f "%Y%m%d_%H%M%S" "$timestamp" "+%B %d, %Y %I:%M:%S %p" 2>/dev/null)
        
        # Extract metrics and info
        total=$(grep "Total Checks Run:" "$report" | awk '{print $4}' | head -n1)
        passed=$(grep "Passed Checks:" "$report" | awk '{print $3}' | head -n1)
        failed=$(grep "Failed Checks:" "$report" | awk '{print $3}' | head -n1)
        compliance=$(grep "Compliance Rate:" "$report" | awk '{print $3}' | tr -d '%' | head -n1)
        
        # Use 0 as default for missing values
        total=${total:-0}
        passed=${passed:-0}
        failed=${failed:-0}
        compliance=${compliance:-0}
        
        # Calculate deltas
        passed_delta=$((passed - prev_passed))
        failed_delta=$((failed - prev_failed))
        
        # Store current values for next iteration
        prev_passed=$passed
        prev_failed=$failed
        
        # Get system information using system_profiler
        hostname=$(hostname)
        model=$(system_profiler SPHardwareDataType | grep "Model Name" | cut -d: -f2- | xargs)
        macos_version=$(sw_vers -productVersion)
        processor=$(sysctl -n machdep.cpu.brand_string)
        memory=$(system_profiler SPHardwareDataType | grep "Memory:" | cut -d: -f2- | xargs)
        
        # Get base filename without extension
        base=$(basename "$report" .txt)
        
        # Generate HTML for this report
        cat >> "$DASHBOARD_DIR/cis-report-dashboard.html" << EOL
                        <div class="border rounded-lg overflow-hidden">
                            <div class="bg-white px-4 py-4">
                                <div class="flex flex-col p-1">
                                    <div class="flex items-center justify-between">
                                        <div>
                                            <h3 class="text-base font-medium text-gray-900">Report from ${formatted_date}</h3>
                                            <div class="mt-0.5 text-sm text-gray-600">
                                                ${hostname} • ${model} • macOS ${macos_version} • ${processor} • ${memory}
                                            </div>
                                        </div>
                                        <div class="flex items-center space-x-4">
                                            <div class="text-lg font-medium">
EOL
        
        # Add delta information if positive
        if [ "$passed_delta" -gt 0 ]; then
            echo "                                                <span class=\"text-green-600\">+${passed_delta} passed</span>" >> "$DASHBOARD_DIR/cis-report-dashboard.html"
        fi
        if [ "$failed_delta" -gt 0 ]; then
            echo "                                                <span class=\"text-red-600 ml-3\">+${failed_delta} failed</span>" >> "$DASHBOARD_DIR/cis-report-dashboard.html"
        fi
        
        cat >> "$DASHBOARD_DIR/cis-report-dashboard.html" << EOL
                                            </div>
                                            <div class="flex items-center space-x-2">
                                                <a href="reports/$(basename "$report")" download class="inline-flex items-center p-1 text-gray-500 hover:text-gray-700" title="Download Raw Report">
                                                    <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                                    </svg>
                                                </a>
                                                <a href="reports/${base}.html" class="inline-flex items-center p-1 text-indigo-600 hover:text-indigo-800" title="View Report">
                                                    <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                                                    </svg>
                                                </a>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mt-1 flex items-center space-x-6">
                                        <div class="text-base text-green-600">
                                            ${passed} passed
                                        </div>
                                        <div class="text-base text-red-600">
                                            ${failed} failed
                                        </div>
                                        <div class="text-base text-gray-600">
                                            ${compliance}% compliance
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
EOL
    fi
done

# Close the HTML
cat >> "$DASHBOARD_DIR/cis-report-dashboard.html" << 'EOL'
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
EOL

echo "Generated reports list: $REPORTS_DIR/reports_list.json"
echo "Generated dashboard: $DASHBOARD_DIR/cis-report-dashboard.html"
