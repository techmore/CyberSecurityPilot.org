#!/usr/bin/env python3
import os
import re
import subprocess
import requests
from datetime import datetime
from urllib.parse import urlparse

def get_valid_domain(domain):
    """Try both www and non-www versions of the domain to find which one works."""
    variants = [
        domain,
        f"www.{domain}" if not domain.startswith('www.') else domain.replace('www.', '')
    ]
    
    for url in variants:
        try:
            response = requests.head(f"https://{url}", timeout=10,
                                   headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'},
                                   allow_redirects=True)
            if response.status_code < 400:
                # If we were redirected, use the final URL's domain
                final_domain = urlparse(response.url).netloc
                if final_domain.startswith('www.'):
                    return final_domain
                return f"www.{final_domain}" if response.url.startswith('https://www.') else final_domain
        except Exception as e:
            print(f"Warning: Could not reach https://{url}: {e}")
    
    return None

def create_wget_command(url, output_dir):
    """Create a wget command with appropriate options for a complete site clone."""
    return [
        'wget',
        '--mirror',  # Mirror the website
        '--convert-links',  # Convert links to work locally
        '--adjust-extension',  # Add appropriate extensions to files
        '--page-requisites',  # Get all assets needed to display the page
        '--no-parent',  # Don't follow links to parent directory
        '--directory-prefix=' + output_dir,  # Set the output directory
        '--no-host-directories',  # Don't create host directories
        #'--wait=2',  # Wait between requests to be polite
        '--random-wait',  # Add random wait time between requests
        '--timeout=20',  # Set timeout to 20 seconds
        '--tries=3',  # Limit retries to 3
        '--no-check-certificate',  # Skip SSL verification if needed
        '--user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"',
        #'--limit-rate=200k',  # Limit download rate
        '--no-verbose',  # Reduce output verbosity
        'https://' + url
    ]

def main():
    # Create output directory with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'website_archives', timestamp)
    os.makedirs(base_output_dir, exist_ok=True)
    
    # Read the dashboard HTML file
    dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dashboard', 'msp-dashboard.html')
    with open(dashboard_path, 'r') as f:
        content = f.read()
    
    # Find all website entries using regex
    website_pattern = r'"name":\s*"([^"]+)"[^}]+"website":\s*"([^"]+)"'
    matches = re.finditer(website_pattern, content)
    
    for match in matches:
        name = match.group(1)
        website = match.group(2)
        
        print(f"\nProcessing website for: {name}")
        print(f"Original URL: {website}")
        
        # Validate and get the correct domain
        valid_domain = get_valid_domain(website)
        if not valid_domain:
            print(f"Skipping {website} - could not find a working domain variant")
            continue
            
        print(f"Using validated domain: {valid_domain}")
        
        # Create a safe directory name
        safe_name = name.replace(' ', '_').replace('/', '_')
        output_dir = os.path.join(base_output_dir, safe_name)
        
        try:
            cmd = create_wget_command(valid_domain, output_dir)
            print(f"Starting download for {valid_domain}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"Successfully cloned website for {name}")
            else:
                print(f"Warning: wget completed with return code {result.returncode}")
                print("Error output:")
                print(result.stderr)
                
        except subprocess.CalledProcessError as e:
            print(f"Error cloning website for {name}: {e}")
            if e.stderr:
                print("Error output:")
                print(e.stderr)
        except Exception as e:
            print(f"Unexpected error for {name}: {e}")

if __name__ == "__main__":
    main()
