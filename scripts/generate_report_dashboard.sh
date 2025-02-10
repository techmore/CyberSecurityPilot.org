#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"

# Get the latest report file
LATEST_REPORT="$1"
if [ -z "$LATEST_REPORT" ]; then
    echo "Usage: $0 <report_file>"
    exit 1
fi

# Extract base name without extension
BASE_NAME=$(basename "$LATEST_REPORT" .txt)
DASHBOARD_FILE="$REPORTS_DIR/${BASE_NAME}.html"

# Extract system information
hostname=$(grep "^Hostname:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
model=$(grep "^Model:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
macos_version=$(grep "^macOS Version:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
processor=$(grep "^Processor:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
memory=$(grep "^Memory:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
filevault_status=$(grep "^FileVault Status:" "$LATEST_REPORT" | cut -d: -f2- | xargs)
sip_status=$(grep "^SIP Status:" "$LATEST_REPORT" | cut -d: -f2- | xargs)

# Create dashboard HTML
cat > "$DASHBOARD_FILE" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Security Report Details</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
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
                                <a :href="'$(basename "$LATEST_REPORT")'" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                    </svg>
                                    Raw Report
                                </a>
                                <a :href="'$(basename "${LATEST_REPORT%.txt}.json")'" download class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
                                    <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                                    </svg>
                                    JSON
                                </a>
                            </div>
                            <a href="../cis-report-dashboard.html" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-gray-600 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                                Back to Reports
                            </a>
                        </div>
                    </div>
                    <div class="flex items-center text-sm text-gray-600 space-x-4">
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                            </svg>
                            <span>$hostname</span>
                        </div>
                        <div class="w-1 h-1 bg-gray-300 rounded-full"></div>
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/>
                            </svg>
                            <span>$model</span>
                        </div>
                        <div class="w-1 h-1 bg-gray-300 rounded-full"></div>
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
                            </svg>
                            <span>$processor</span>
                        </div>
                        <div class="w-1 h-1 bg-gray-300 rounded-full"></div>
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"/>
                            </svg>
                            <span>$memory</span>
                        </div>
                        <div class="w-1 h-1 bg-gray-300 rounded-full"></div>
                        <div class="flex items-center space-x-1">
                            <svg class="h-4 w-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2V5a2 2 0 00-2-2H6a2 2 0 00-2 2v14a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                            </svg>
                            <span>macOS $macos_version</span>
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
EOL

# Add summary stats
total_checks=$(grep -c "^\[.*\]\[.*\]" "$LATEST_REPORT")
passed_checks=$(grep -c "^\[.*\]\[Pass\]" "$LATEST_REPORT")
failed_checks=$(grep -c "^\[.*\]\[Fail\]" "$LATEST_REPORT")

if [ "$total_checks" -gt 0 ]; then
    compliance_rate=$((passed_checks * 100 / total_checks))
else
    compliance_rate=0
fi

cat >> "$DASHBOARD_FILE" << EOL
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

            <!-- Test Results -->
            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-5 sm:p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-lg font-medium text-gray-900">Test Results</h2>
                        <button onclick="expandAll()" class="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                            Expand All
                        </button>
                    </div>
                    <div class="space-y-4">
EOL

# Process each section and its tests
current_section=""
while IFS= read -r line; do
    # Remove ANSI color codes for easier parsing
    clean_line=$(echo "$line" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
    
    # Check for section headers (bold text with section number)
    if [[ "$clean_line" =~ ^[0-9]+\.[[:space:]] ]]; then
        section_name="$clean_line"
        if [ -n "$current_section" ]; then
            echo "                    </div>" >> "$DASHBOARD_FILE"
        fi
        current_section="$section_name"
        cat >> "$DASHBOARD_FILE" << EOL
                        <div class="mt-8 first:mt-0">
                            <h3 class="text-lg font-medium text-gray-900 mb-4">$section_name</h3>
EOL
    # Process test results (lines with [Pass] or [Fail])
    elif [[ "$clean_line" =~ ^\[(Pass|Fail)\][[:space:]]([0-9]+\.[0-9]+\.[0-9]+[[:space:]].*)$ ]]; then
        status="${BASH_REMATCH[1]}"
        test_line="${BASH_REMATCH[2]}"
        
        # Extract test ID and description
        if [[ "$test_line" =~ ^([0-9]+\.[0-9]+\.[0-9]+)[[:space:]]+(.*)$ ]]; then
            test_id="${BASH_REMATCH[1]}"
            description="${BASH_REMATCH[2]}"
            
            # Get remediation if status is Fail
            remediation=""
            if [ "$status" = "Fail" ]; then
                next_line=$(grep -A 1 "^$test_id" "$LATEST_REPORT" | grep "Remediation:" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | sed 's/Remediation: //')
                if [ ! -z "$next_line" ]; then
                    remediation="$next_line"
                fi
            fi
            
            # Set status colors
            if [ "$status" = "Pass" ]; then
                status_color="green"
                status_icon='<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>'
            else
                status_color="red"
                status_icon='<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>'
            fi
            
            cat >> "$DASHBOARD_FILE" << EOL
                            <div class="border rounded-lg overflow-hidden mb-4" x-data="{ open: false }">
                                <button @click="open = !open" class="w-full px-4 py-3 flex items-center justify-between bg-gray-50 hover:bg-gray-100 focus:outline-none">
                                    <div class="flex items-center space-x-3">
                                        <div class="flex-shrink-0">
                                            <span class="inline-flex items-center justify-center h-8 w-8 rounded-full bg-${status_color}-100">
                                                <svg class="h-5 w-5 text-${status_color}-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    $status_icon
                                                </svg>
                                            </span>
                                        </div>
                                        <div class="text-left">
                                            <div class="text-sm font-medium text-gray-900">$test_id</div>
                                            <div class="text-sm text-gray-500">$description</div>
                                        </div>
                                    </div>
                                    <svg class="h-5 w-5 text-gray-400" :class="{'transform rotate-180': open}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                    </svg>
                                </button>
EOL
            
            if [ -n "$remediation" ]; then
                cat >> "$DASHBOARD_FILE" << EOL
                                <div x-show="open" class="px-4 py-3 bg-white">
                                    <div class="mt-2">
                                        <div class="text-sm font-medium text-gray-900">Remediation:</div>
                                        <div class="mt-1 text-sm text-gray-500">$remediation</div>
                                    </div>
                                </div>
EOL
            fi
            
            echo "                            </div>" >> "$DASHBOARD_FILE"
        fi
    fi
done < "$LATEST_REPORT"

# Close any open section
if [ -n "$current_section" ]; then
    echo "                    </div>" >> "$DASHBOARD_FILE"
fi

# Add closing tags and JavaScript
cat >> "$DASHBOARD_FILE" << 'EOL'
                    </div>
                </div>
            </div>
        </main>
    </div>
    <script>
        function expandAll() {
            document.querySelectorAll('[x-data]').forEach(el => {
                if (el.__x) {
                    el.__x.$data.open = true;
                }
            });
        }
    </script>
</body>
</html>
EOL

echo "Generated dashboard: $DASHBOARD_FILE"
