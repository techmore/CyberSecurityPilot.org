#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"

# Function to generate a dashboard for a report
generate_dashboard() {
    local report_file="$1"
    local json_file="${report_file%.txt}.json"
    local dashboard_file="${report_file%.txt}.html"
    local timestamp=$(basename "$report_file" | grep -Eo '[0-9]{8}_[0-9]{6}')
    
    # Extract data from report
    local total_checks=$(grep "Total Checks Run:" "$report_file" | awk '{print $4}')
    local passed_checks=$(grep "Passed Checks:" "$report_file" | awk '{print $3}')
    local failed_checks=$(grep "Failed Checks:" "$report_file" | awk '{print $3}')
    local compliance_rate=$(grep "Compliance Rate:" "$report_file" | awk '{print $3}' | tr -d '%')
    local model=$(system_profiler SPHardwareDataType 2>/dev/null | grep "Model Name" | cut -d: -f2 | xargs)
    local macos_version=$(sw_vers -productVersion)
    
    # Create dashboard HTML
    cat > "$dashboard_file" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Report - $(date -r "$report_file" "+%Y-%m-%d %H:%M:%S")</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-white shadow">
            <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center">
                    <div class="flex items-center space-x-4">
                        <a href="../cis-report-dashboard.html" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-gray-700 bg-gray-100 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                            <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
                            </svg>
                            Back to Reports
                        </a>
                        <h1 class="text-3xl font-bold text-gray-900">
                            CIS Security Report
                        </h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <div class="text-sm text-gray-500">
                            Generated on $(date -r "$report_file" "+%Y-%m-%d %H:%M:%S")
                        </div>
                        <div class="flex space-x-2">
                            <a href="$(basename "$report_file")" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                                Download Report
                            </a>
                            <a href="$(basename "$json_file")" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                                <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                </svg>
                                Download JSON
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <!-- Summary Cards -->
            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4 mb-8">
                <div class="bg-white overflow-hidden shadow rounded-lg">
                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Compliance Rate</dt>
                        <dd class="mt-1 text-3xl font-semibold text-gray-900">$compliance_rate%</dd>
                    </div>
                </div>
                <div class="bg-white overflow-hidden shadow rounded-lg">
                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Total Checks</dt>
                        <dd class="mt-1 text-3xl font-semibold text-gray-900">$total_checks</dd>
                    </div>
                </div>
                <div class="bg-white overflow-hidden shadow rounded-lg">
                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Passed Checks</dt>
                        <dd class="mt-1 text-3xl font-semibold text-green-600">$passed_checks</dd>
                    </div>
                </div>
                <div class="bg-white overflow-hidden shadow rounded-lg">
                    <div class="px-4 py-5 sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Failed Checks</dt>
                        <dd class="mt-1 text-3xl font-semibold text-red-600">$failed_checks</dd>
                    </div>
                </div>
            </div>

            <!-- System Information -->
            <div class="bg-white shadow rounded-lg mb-8">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">System Information</h2>
                    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                        <div>
                            <dt class="text-sm font-medium text-gray-500">Model</dt>
                            <dd class="mt-1 text-sm text-gray-900">$model</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">macOS Version</dt>
                            <dd class="mt-1 text-sm text-gray-900">$macos_version</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">Report Date</dt>
                            <dd class="mt-1 text-sm text-gray-900">$(date -r "$report_file" "+%Y-%m-%d %H:%M:%S")</dd>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Checks -->
            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-5 sm:p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-lg font-medium text-gray-900">Security Checks</h2>
                        <div class="flex space-x-2">
                            <button @click="Object.keys($refs).forEach(key => { if(key.startsWith('section')) $refs[key].setAttribute('x-show', 'true') })" class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-gray-700 bg-gray-100 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Expand All
                            </button>
                            <button @click="Object.keys($refs).forEach(key => { if(key.startsWith('section')) $refs[key].setAttribute('x-show', 'false') })" class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-gray-700 bg-gray-100 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Collapse All
                            </button>
                        </div>
                    </div>
                    <div class="space-y-4" x-data="{ openSection: null }">
EOL
    
    # Process each section and its checks
    current_section=""
    while IFS= read -r line; do
        # Check for section headers
        if [[ "$line" =~ ^([0-9]+\.[^-]+)[-]+$ ]]; then
            if [ -n "$current_section" ]; then
                echo "                        </div>" >> "$dashboard_file"
                echo "                    </div>" >> "$dashboard_file"
            fi
            current_section="${BASH_REMATCH[1]}"
            cat >> "$dashboard_file" << EOL
                        <div class="border rounded-lg overflow-hidden">
                            <div class="bg-gray-50 px-4 py-3 flex items-center justify-between cursor-pointer"
                                 @click="openSection = openSection === '$current_section' ? null : '$current_section'">
                                <h3 class="text-sm font-medium text-gray-900">$current_section</h3>
                                <svg class="h-5 w-5 text-gray-400 transform transition-transform" 
                                     :class="{'rotate-180': openSection === '$current_section'}"
                                     fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                </svg>
                            </div>
                            <div class="divide-y divide-gray-200" x-show="openSection === '$current_section'" x-cloak x-ref="section$current_section">
EOL
        # Check for test results
        elif [[ "$line" =~ ^([0-9]+\.[0-9]+[[:space:]].*)\[(.*)\]$ ]]; then
            test_line="${BASH_REMATCH[1]}"
            status="${BASH_REMATCH[2]}"
            
            # Extract test ID and description
            if [[ "$test_line" =~ ^([0-9]+\.[0-9]+)[[:space:]]+(.*)$ ]]; then
                test_id="${BASH_REMATCH[1]}"
                description="${BASH_REMATCH[2]}"
                
                # Get remediation if status is Fail
                remediation=""
                if [ "$status" = "Fail" ]; then
                    while IFS= read -r next_line; do
                        if [[ "$next_line" =~ ^[[:space:]]*Remediation:[[:space:]]*(.*)$ ]]; then
                            remediation="${BASH_REMATCH[1]}"
                            break
                        elif [[ "$next_line" =~ ^[0-9]+\.[0-9]+ || "$next_line" =~ ^[0-9]+\.[^-]+[-]+$ ]]; then
                            break
                        fi
                    done
                fi
                
                # Add check to dashboard
                status_color="gray"
                if [ "$status" = "Pass" ]; then
                    status_color="green"
                elif [ "$status" = "Fail" ]; then
                    status_color="red"
                fi
                
                cat >> "$dashboard_file" << EOL
                                <div class="px-4 py-3">
                                    <div class="flex items-center justify-between">
                                        <div class="flex items-center space-x-3">
                                            <div class="text-${status_color}-500 flex-shrink-0">
EOL
                
                if [ "$status" = "Pass" ]; then
                    cat >> "$dashboard_file" << EOL
                                                <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                                                </svg>
EOL
                elif [ "$status" = "Fail" ]; then
                    cat >> "$dashboard_file" << EOL
                                                <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                                </svg>
EOL
                else
                    cat >> "$dashboard_file" << EOL
                                                <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                                </svg>
EOL
                fi
                
                cat >> "$dashboard_file" << EOL
                                            </div>
                                            <div>
                                                <p class="text-sm font-medium text-gray-900">$test_id $description</p>
EOL
                
                if [ -n "$remediation" ]; then
                    cat >> "$dashboard_file" << EOL
                                                <div class="mt-2 text-sm text-gray-500">
                                                    <div class="font-medium text-gray-700">Remediation:</div>
                                                    <p class="mt-1">$remediation</p>
                                                </div>
EOL
                fi
                
                cat >> "$dashboard_file" << EOL
                                            </div>
                                        </div>
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${status_color}-100 text-${status_color}-800">
                                            $status
                                        </span>
                                    </div>
                                </div>
EOL
            fi
        fi
    done < "$report_file"
    
    # Close any open section
    if [ -n "$current_section" ]; then
        echo "                        </div>" >> "$dashboard_file"
        echo "                    </div>" >> "$dashboard_file"
    fi
    
    # Close the HTML file
    cat >> "$dashboard_file" << EOL
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
EOL
    
    echo "Generated dashboard: $dashboard_file"
}

# Process the latest report or a specific report if provided
if [ $# -eq 0 ]; then
    latest_report=$(ls -t "$REPORTS_DIR"/cis_security_report_*.txt | head -n1)
    if [ -n "$latest_report" ]; then
        generate_dashboard "$latest_report"
    else
        echo "No report files found"
        exit 1
    fi
else
    for report in "$@"; do
        if [ -f "$report" ]; then
            generate_dashboard "$report"
        else
            echo "Report file not found: $report"
        fi
    done
fi
