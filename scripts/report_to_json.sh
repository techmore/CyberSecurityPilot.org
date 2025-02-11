#!/bin/bash

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPORTS_DIR="$SCRIPT_DIR/../dashboard/reports"
LATEST_REPORT=$(ls -t "$REPORTS_DIR"/cis_security_report_*.txt | head -n1)

if [ -z "$LATEST_REPORT" ]; then
    echo "No report files found"
    exit 1
fi

# Create JSON output file
JSON_OUTPUT="${LATEST_REPORT%.txt}.json"

# Initialize variables
current_section=""
declare -a all_sections

# Process the report file line by line
{
    echo "{"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"report_file\": \"$LATEST_REPORT\","
    
    # Extract summary information
    total_checks=$(grep "Total Checks Run:" "$LATEST_REPORT" | awk '{print $4}')
    passed_checks=$(grep "Passed Checks:" "$LATEST_REPORT" | awk '{print $3}')
    failed_checks=$(grep "Failed Checks:" "$LATEST_REPORT" | awk '{print $3}')
    compliance_rate=$(grep "Compliance Rate:" "$LATEST_REPORT" | awk '{print $3}' | tr -d '%')
    
    echo "  \"summary\": {"
    echo "    \"total_checks\": $total_checks,"
    echo "    \"passed_checks\": $passed_checks,"
    echo "    \"failed_checks\": $failed_checks,"
    echo "    \"compliance_rate\": $compliance_rate"
    echo "  },"
    
    # Extract system information
    echo "  \"system_info\": {"
    echo "    \"system_information\": {"
    echo "      \"model\": \"$(system_profiler SPHardwareDataType 2>/dev/null | grep "Model Name" | cut -d: -f2 | xargs)\","
    echo "      \"macosversion\": \"$(sw_vers -productVersion)\""
    echo "    }"
    echo "  },"
    
    echo "  \"sections\": ["
    
    first_section=true
    while IFS= read -r line; do
        # Check for section headers
        if [[ "$line" =~ ^([0-9]+\.[^-]+)[-]+$ ]]; then
            if [ "$current_section" != "" ]; then
                if [ "$first_section" = true ]; then
                    first_section=false
                else
                    echo ","
                fi
                echo "    {"
                echo "      \"title\": \"$current_section\","
                echo "      \"checks\": ["
                echo "$section_checks" | sed 's/,$//'
                echo "      ]"
                echo "    }"
            fi
            current_section="${BASH_REMATCH[1]}"
            section_checks=""
            all_sections+=("$current_section")
            continue
        fi
        
        # Check for test results
        if [[ "$line" =~ ^([0-9]+\.[0-9]+[[:space:]].*)\[(.*)\]$ ]]; then
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
                
                # Add check to section
                if [ "$section_checks" != "" ]; then
                    section_checks="$section_checks,"
                fi
                section_checks="$section_checks
        {
          \"id\": \"$test_id\",
          \"title\": \"$description\",
          \"status\": \"$status\"$([ -n "$remediation" ] && echo ",
          \"remediation\": \"$remediation\"")
        }"
            fi
        fi
    done < "$LATEST_REPORT"
    
    # Output last section if exists
    if [ "$current_section" != "" ]; then
        if [ "$first_section" = true ]; then
            first_section=false
        else
            echo ","
        fi
        echo "    {"
        echo "      \"title\": \"$current_section\","
        echo "      \"checks\": ["
        echo "$section_checks" | sed 's/,$//'
        echo "      ]"
        echo "    }"
    fi
    
    echo "  ]"
    echo "}"
} > "$JSON_OUTPUT"

echo "JSON report generated: $JSON_OUTPUT"

# Function to generate HTML for a report
generate_html() {
    local report_file="$1"
    local html_file="${report_file%.txt}.html"
    local json_file="${report_file%.txt}.json"
    
    # Extract metrics
    local total=$(grep "Total Checks Run:" "$report_file" | awk '{print $4}' | head -n1)
    local passed=$(grep "Passed Checks:" "$report_file" | awk '{print $3}' | head -n1)
    local failed=$(grep "Failed Checks:" "$report_file" | awk '{print $3}' | head -n1)
    local compliance=$(grep "Compliance Rate:" "$report_file" | awk '{print $3}' | tr -d '%' | head -n1)
    
    # Create HTML file
    cat > "$html_file" << EOL
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
        <header class="bg-white shadow">
            <div class="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center">
                    <h1 class="text-3xl font-bold text-gray-900">
                        CIS Security Report Details
                    </h1>
                    <a href="../cis-report-dashboard.html" class="text-indigo-600 hover:text-indigo-800">
                        ← Back to Dashboard
                    </a>
                </div>
            </div>
        </header>

        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div class="bg-white shadow rounded-lg mb-6">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">Report Summary</h2>
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div class="p-4 bg-gray-50 rounded-lg">
                            <div class="text-sm font-medium text-gray-500">Total Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-gray-900">$total</div>
                        </div>
                        <div class="p-4 bg-green-50 rounded-lg">
                            <div class="text-sm font-medium text-green-600">Passed Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-green-700">$passed</div>
                        </div>
                        <div class="p-4 bg-red-50 rounded-lg">
                            <div class="text-sm font-medium text-red-600">Failed Checks</div>
                            <div class="mt-1 text-3xl font-semibold text-red-700">$failed</div>
                        </div>
                        <div class="p-4 bg-blue-50 rounded-lg">
                            <div class="text-sm font-medium text-blue-600">Compliance Rate</div>
                            <div class="mt-1 text-3xl font-semibold text-blue-700">$compliance%</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="bg-white shadow rounded-lg">
                <div class="px-4 py-5 sm:p-6">
                    <h2 class="text-lg font-medium text-gray-900 mb-4">Detailed Results</h2>
                    <div class="prose max-w-none">
                        <pre class="whitespace-pre-wrap text-sm text-gray-600">$(cat "$report_file")</pre>
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
EOL

    echo "Generated HTML report: $html_file"
}

# Generate HTML report
generate_html "$LATEST_REPORT"

# Generate dashboard
"$SCRIPT_DIR/generate_report_dashboard.sh" "$LATEST_REPORT"

# Update reports list
"$SCRIPT_DIR/update_reports_list.sh"

echo "Report processing complete!"
