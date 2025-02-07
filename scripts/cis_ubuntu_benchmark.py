#!/usr/bin/env python3
"""
CIS Ubuntu Linux 22.04 LTS Benchmark Assessment Script
This script performs a security assessment based on CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0
It generates both text and HTML reports of the assessment results.
"""

import os
import subprocess
import json
import datetime
import re
from typing import Dict, List, Tuple, Optional

class CISBenchmark:
    def __init__(self):
        self.results = {}
        self.timestamp = datetime.datetime.now().isoformat()
        
    def run_command(self, command: str) -> Tuple[str, int]:
        """Run a shell command and return its output and exit code."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return (result.stdout + result.stderr).strip(), result.returncode
        except Exception as e:
            return str(e), 1

    def check_1_1_1_1(self) -> Dict:
        """Ensure mounting of cramfs filesystems is disabled."""
        check_id = "1.1.1.1"
        title = "Ensure mounting of cramfs filesystems is disabled"
        
        # Check if module is loaded
        output1, _ = self.run_command("lsmod | grep cramfs")
        # Check if module is disabled
        output2, _ = self.run_command("modprobe -n -v cramfs")
        
        status = "Pass" if not output1 and "install /bin/true" in output2 else "Fail"
        
        return {
            "id": check_id,
            "title": title,
            "status": status,
            "output": f"Module loaded check: {output1}\nModule disabled check: {output2}",
            "description": "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used for malicious purposes.",
            "rationale": "Removing support for unneeded filesystem types reduces the local attack surface of the system.",
            "remediation": """
# Run the following commands to unload and disable the cramfs module:
rmmod cramfs
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
"""
        }

    def check_1_1_1_2(self) -> Dict:
        """Ensure mounting of freevxfs filesystems is disabled."""
        check_id = "1.1.1.2"
        title = "Ensure mounting of freevxfs filesystems is disabled"
        
        output1, _ = self.run_command("lsmod | grep freevxfs")
        output2, _ = self.run_command("modprobe -n -v freevxfs")
        
        status = "Pass" if not output1 and "install /bin/true" in output2 else "Fail"
        
        return {
            "id": check_id,
            "title": title,
            "status": status,
            "output": f"Module loaded check: {output1}\nModule disabled check: {output2}",
            "description": "The freevxfs filesystem type is a free version of the Veritas type filesystem. This is a legacy filesystem.",
            "rationale": "Removing support for unneeded filesystem types reduces the local attack surface of the system.",
            "remediation": """
# Run the following commands to unload and disable the freevxfs module:
rmmod freevxfs
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
"""
        }

    def check_1_1_1_3(self) -> Dict:
        """Ensure mounting of jffs2 filesystems is disabled."""
        check_id = "1.1.1.3"
        title = "Ensure mounting of jffs2 filesystems is disabled"
        
        output1, _ = self.run_command("lsmod | grep jffs2")
        output2, _ = self.run_command("modprobe -n -v jffs2")
        
        status = "Pass" if not output1 and "install /bin/true" in output2 else "Fail"
        
        return {
            "id": check_id,
            "title": title,
            "status": status,
            "output": f"Module loaded check: {output1}\nModule disabled check: {output2}",
            "description": "The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.",
            "rationale": "Removing support for unneeded filesystem types reduces the local attack surface of the system.",
            "remediation": """
# Run the following commands to unload and disable the jffs2 module:
rmmod jffs2
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
"""
        }

    def check_1_1_2(self) -> Dict:
        """Ensure /tmp is configured."""
        check_id = "1.1.2"
        title = "Ensure /tmp is configured"
        
        output1, _ = self.run_command("findmnt -n /tmp")
        output2, _ = self.run_command("grep -E '\\s/tmp\\s' /etc/fstab")
        
        status = "Pass" if output1 and output2 else "Fail"
        
        return {
            "id": check_id,
            "title": title,
            "status": status,
            "output": f"Current mount: {output1}\nfstab entry: {output2}",
            "description": "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or create it using systemd.",
            "rationale": "Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition.",
            "remediation": """
# Edit /etc/fstab and add the following line:
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

# Run the following commands to mount /tmp:
mount -o remount,nodev /tmp
"""
        }

    def check_1_1_3(self) -> Dict:
        """Ensure nodev option set on /tmp partition."""
        check_id = "1.1.3"
        title = "Ensure nodev option set on /tmp partition"
        
        output, _ = self.run_command("findmnt -n /tmp | grep -v nodev")
        
        status = "Pass" if not output else "Fail"
        
        return {
            "id": check_id,
            "title": title,
            "status": status,
            "output": f"Mount options: {output}",
            "description": "The nodev mount option specifies that the filesystem cannot contain special devices.",
            "rationale": "Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp.",
            "remediation": """
# Edit /etc/fstab and add nodev to the fourth field of the /tmp entry:
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0

# Run the following command to remount /tmp:
mount -o remount,nodev /tmp
"""
        }

    def run_all_checks(self) -> None:
        """Run all benchmark checks and store results."""
        check_methods = [method for method in dir(self) if method.startswith('check_')]
        for method in check_methods:
            result = getattr(self, method)()
            self.results[result['id']] = result

    def generate_text_report(self, filename: str) -> None:
        """Generate a detailed text report of all check results."""
        with open(filename, 'w') as f:
            f.write("CIS Ubuntu Linux 22.04 LTS Benchmark Assessment Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Generated: {self.timestamp}\n\n")
            
            # Summary
            total = len(self.results)
            passed = sum(1 for r in self.results.values() if r['status'] == 'Pass')
            failed = total - passed
            
            f.write("Summary:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total checks: {total}\n")
            f.write(f"Passed: {passed}\n")
            f.write(f"Failed: {failed}\n")
            f.write(f"Compliance score: {(passed/total)*100:.1f}%\n\n")
            
            # Detailed Results
            f.write("Detailed Results:\n")
            f.write("=" * 60 + "\n\n")
            
            for check_id, result in sorted(self.results.items()):
                f.write(f"Check {check_id}: {result['title']}\n")
                f.write("-" * 60 + "\n")
                f.write(f"Status: {result['status']}\n")
                f.write(f"Description: {result['description']}\n")
                f.write(f"Rationale: {result['rationale']}\n")
                f.write("\nCheck Output:\n{}\n".format(result['output']))
                if result['status'] == 'Fail':
                    f.write("\nRemediation:\n{}\n".format(result['remediation']))
                f.write("\n" + "=" * 60 + "\n\n")

    def generate_html_report(self, filename: str) -> None:
        """Generate a detailed HTML report of all check results."""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Ubuntu Linux 22.04 LTS Benchmark Assessment Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .check {
            margin: 20px 0;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .check.pass {
            border-left: 4px solid #2ecc71;
        }
        .check.fail {
            border-left: 4px solid #e74c3c;
        }
        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        .status.pass {
            background: #2ecc71;
            color: white;
        }
        .status.fail {
            background: #e74c3c;
            color: white;
        }
        pre {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .remediation {
            background: #fff3cd;
            padding: 15px;
            border-radius: 4px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>CIS Ubuntu Linux 22.04 LTS Benchmark Assessment Report</h1>
        <p>Generated: {timestamp}</p>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>Total checks: {total}</p>
            <p>Passed: {passed}</p>
            <p>Failed: {failed}</p>
            <p>Compliance score: {score:.1f}%</p>
        </div>

        <h2>Detailed Results</h2>
        {detailed_results}
    </div>
</body>
</html>
"""
        
        check_template = """
        <div class="check {status_class}">
            <h3>Check {id}: {title}</h3>
            <p><span class="status {status_class}">{status}</span></p>
            <p><strong>Description:</strong> {description}</p>
            <p><strong>Rationale:</strong> {rationale}</p>
            <p><strong>Check Output:</strong></p>
            <pre>{output}</pre>
            {remediation_html}
        </div>
"""
        
        # Generate summary data
        total = len(self.results)
        passed = sum(1 for r in self.results.values() if r['status'] == 'Pass')
        failed = total - passed
        score = (passed/total)*100
        
        # Generate detailed results HTML
        detailed_results = ""
        for check_id, result in sorted(self.results.items()):
            status_class = result['status'].lower()
            remediation_html = f"""
            <div class="remediation">
                <h4>Remediation:</h4>
                <pre>{result['remediation']}</pre>
            </div>
""" if result['status'] == 'Fail' else ""
            
            detailed_results += check_template.format(
                id=check_id,
                title=result['title'],
                status=result['status'],
                status_class=status_class,
                description=result['description'],
                rationale=result['rationale'],
                output=result['output'],
                remediation_html=remediation_html
            )
        
        # Generate final HTML
        html_content = html_template.format(
            timestamp=self.timestamp,
            total=total,
            passed=passed,
            failed=failed,
            score=score,
            detailed_results=detailed_results
        )
        
        with open(filename, 'w') as f:
            f.write(html_content)

def main():
    # Create benchmark instance
    benchmark = CISBenchmark()
    
    # Run all checks
    print("Running CIS Ubuntu Linux 22.04 LTS Benchmark checks...")
    benchmark.run_all_checks()
    
    # Generate reports
    print("Generating reports...")
    benchmark.generate_text_report('cis_ubuntu_benchmark_report.txt')
    benchmark.generate_html_report('cis_ubuntu_benchmark_report.html')
    
    print("Assessment complete. Reports have been generated:")
    print("- Text report: cis_ubuntu_benchmark_report.txt")
    print("- HTML report: cis_ubuntu_benchmark_report.html")

if __name__ == "__main__":
    main()
