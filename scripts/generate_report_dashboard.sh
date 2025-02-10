#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"

# Get the report file from command line argument
LATEST_REPORT="$1"
if [ -z "$LATEST_REPORT" ]; then
    echo "Usage: $0 <report_file>"
    exit 1
fi

# Extract base name without extension
BASE_NAME=$(basename "$LATEST_REPORT" .txt)
DASHBOARD_FILE="$REPORTS_DIR/${BASE_NAME}.html"

# Get system information
hostname=$(hostname)
model=$(system_profiler SPHardwareDataType | grep "Model Name" | cut -d: -f2- | xargs)
macos_version=$(sw_vers -productVersion)
processor=$(sysctl -n machdep.cpu.brand_string)
memory=$(system_profiler SPHardwareDataType | grep "Memory:" | cut -d: -f2- | xargs)
filevault_status=$(fdesetup status | awk '{print $1}')
sip_status=$(csrutil status | awk '{print $5}')

# Start the HTML file
cat > "$DASHBOARD_FILE" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Report Details</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-white shadow">
            <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
                <div class="flex flex-col space-y-4">
                    <div class="flex justify-between items-center">
                        <h1 class="text-3xl font-bold text-gray-900">
                            CIS Security Report Details
                        </h1>
                        <div class="flex items-center space-x-4">
                            <div class="flex space-x-2">
                                <a href="${BASE_NAME}.txt" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                    </svg>
                                    Raw Report
                                </a>
                                <a href="${BASE_NAME}.json" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                    </svg>
                                    JSON
                                </a>
                            </div>
                            <a href="../cis-report-dashboard.html" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-gray-700 bg-gray-100 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7"/>
                                </svg>
                                Back to Dashboard
                            </a>
                        </div>
                    </div>
                    <div class="flex items-center text-sm text-gray-600 space-x-4">
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                            <span>$hostname</span>
                        </div>
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                            </svg>
                            <span>$macos_version</span>
                        </div>
                    </div>
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <!-- Summary -->
            <div class="bg-white shadow rounded-lg mb-6">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">Report Summary</h2>
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div class="bg-gray-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-gray-500">Total Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-gray-900">$total_checks</div>
                        </div>
                        <div class="bg-green-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-green-600">Passed Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-green-700">$passed_checks</div>
                        </div>
                        <div class="bg-red-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-red-600">Failed Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-red-700">$failed_checks</div>
                        </div>
                        <div class="bg-blue-50 p-4 rounded-lg">
                            <div class="text-sm font-medium text-blue-600">Compliance Rate</div>
                            <div class="mt-1 text-3xl font-semibold text-blue-700">$compliance_rate%</div>
                        </div>
                    </div>
                </div>
            </div>
EOL

# Process the report file to remove ANSI color codes
clean_report=$(cat "$LATEST_REPORT" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')

# Calculate total checks and compliance rate
total_checks=$(echo "$clean_report" | grep -c "^\[.*\]")
passed_checks=$(echo "$clean_report" | grep -c "^\[Pass\]")
failed_checks=$(echo "$clean_report" | grep -c "^\[Fail\]")

# Calculate compliance rate, handle division by zero
if [ "$total_checks" -gt 0 ]; then
    compliance_rate=$((passed_checks * 100 / total_checks))
else
    compliance_rate=0
fi

# Process each section and its tests
current_section=""
while IFS= read -r line; do
    # Remove ANSI color codes for easier parsing
    clean_line=$(echo "$line" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
    
    # Check for section headers (bold text with section number)
    if [[ "$clean_line" =~ ^[0-9]+\.[[:space:]].*$ ]]; then
        # If there was a previous section, close it
        if [ -n "$current_section" ]; then
            echo "                    </div>" >> "$DASHBOARD_FILE"
        fi
        
        # Start new section
        current_section="$clean_line"
        echo "                    <div class=\"mb-8\">" >> "$DASHBOARD_FILE"
        echo "                        <h3 class=\"text-lg font-medium text-gray-900 mb-4\">$current_section</h3>" >> "$DASHBOARD_FILE"
    
    # Process test results (lines with [Pass] or [Fail])
    elif [[ "$clean_line" =~ ^\[([[:alnum:]]+)\][[:space:]]([0-9]+\.[0-9]+\.[0-9]+[[:space:]].*)$ ]]; then
        status="${BASH_REMATCH[1]}"
        test_line="${BASH_REMATCH[2]}"
        
        # Extract test number and description
        if [[ "$test_line" =~ ^([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+(.*)$ ]]; then
            test_number="${BASH_REMATCH[1]}"
            description="${BASH_REMATCH[2]}"
            
            # Set status color and icon
            if [ "$status" = "Pass" ]; then
                status_color="green"
                icon_path="M5 13l4 4L19 7"
            else
                status_color="red"
                icon_path="M6 18L18 6M6 6l12 12"
            fi
            
            # Write test result to file
            cat >> "$DASHBOARD_FILE" << EOL
                            <div class="border rounded-lg overflow-hidden mb-4">
                                <div class="px-4 py-3 flex items-center justify-between bg-gray-50">
                                    <div class="flex items-center space-x-3">
                                        <div class="flex-shrink-0">
                                            <span class="inline-flex items-center justify-center h-8 w-8 rounded-full bg-${status_color}-100">
                                                <svg class="h-5 w-5 text-${status_color}-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${icon_path}"/>
                                                </svg>
                                            </span>
                                        </div>
                                        <div class="text-sm text-gray-900">
                                            <span class="font-medium">$test_number</span>
                                            <span class="mx-2">-</span>
                                            <span>$description</span>
                                        </div>
                                    </div>
                                    <div class="text-sm text-${status_color}-600 font-medium">[$status]</div>
                                </div>
EOL
            
            # Add remediation if it exists
            if [ "$status" = "Fail" ]; then
                next_line=$(grep -A 1 "^$test_number" "$LATEST_REPORT" | grep "Remediation:" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | sed 's/Remediation: //')
                if [ ! -z "$next_line" ]; then
                    cat >> "$DASHBOARD_FILE" << EOL
                                <div class="px-4 py-3 bg-gray-50 border-t">
                                    <div class="text-sm text-gray-600">
                                        <span class="font-medium">Remediation:</span>
                                        <pre class="mt-1 text-sm text-gray-800 whitespace-pre-wrap">$next_line</pre>
                                    </div>
                                </div>
EOL
                fi
            fi
            
            # Close the test result div
            echo "                            </div>" >> "$DASHBOARD_FILE"
        fi
    fi
done < "$LATEST_REPORT"

# Close any open section
if [ -n "$current_section" ]; then
    echo "                    </div>" >> "$DASHBOARD_FILE"
fi

# Add system info section
cat >> "$DASHBOARD_FILE" << EOL
            <!-- System Info -->
            <div class="bg-white shadow rounded-lg mb-6">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">System Information</h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">Hostname</div>
                                <div class="mt-1 text-sm text-gray-900">${hostname}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2V5a2 2 0 00-2-2H6a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">Model</div>
                                <div class="mt-1 text-sm text-gray-900">${model}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">Processor</div>
                                <div class="mt-1 text-sm text-gray-900">${processor}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">Memory</div>
                                <div class="mt-1 text-sm text-gray-900">${memory}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2V5a2 2 0 00-2-2H6a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">FileVault Status</div>
                                <div class="mt-1 text-sm text-gray-900">${filevault_status}</div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <svg class="h-6 w-6 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2V5a2 2 0 00-2-2H6a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                                </svg>
                            </div>
                            <div>
                                <div class="text-sm font-medium text-gray-500">SIP Status</div>
                                <div class="mt-1 text-sm text-gray-900">${sip_status}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Test Results -->
            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">Test Results</h2>
                    <div class="space-y-4">
EOL

# Add closing tags
cat >> "$DASHBOARD_FILE" << EOL
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
EOL

echo "Generated dashboard: $DASHBOARD_FILE"
