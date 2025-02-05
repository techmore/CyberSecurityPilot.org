#!/bin/bash

# https://dnsdumpster.com
# dig +trace www.dvfriends.org
# nslookup admin.dvfriends.org
# sudo nmap -Pn -sV --top-ports 1000 -A --script vulners,http-enum,ssl-enum-ciphers bfs.org > domain.org



# Define the domain to audit
DOMAIN="dvfriends.org"

# Temporary output files
DNS_RECORDS_FILE="dns_records.txt"
SUBDOMAINS_FILE="subdomains.txt"
WHOIS_FILE="whois.txt"
CRT_FILE="crtsh_results.txt"

# Create table header
echo -e "TYPE\tHOSTNAME\tVALUE" > dns_table.txt

# Function to query different DNS records
query_dns() {
    local hostname=$1
    local record_type=$2
    dig $hostname $record_type +short | while read -r line; do
        echo -e "$record_type\t$hostname\t$line" >> dns_table.txt
    done
}

# Function to perform reverse DNS lookup
reverse_dns() {
    local ip=$1
    host $ip | awk '/domain name pointer/ {print $5}' | while read -r ptr; do
        echo -e "PTR\t$ip\t$ptr" >> dns_table.txt
    done
}

# Function to check for zone transfers
check_axfr() {
    echo "Checking for zone transfer on $DOMAIN..."
    dig @$1 $DOMAIN AXFR +short >> dns_table.txt
    if [ $? -eq 0 ]; then
        echo -e "\nZone transfer successful for $1\n" >> dns_table.txt
    else
        echo -e "\nZone transfer failed for $1\n" >> dns_table.txt
    fi
}

# Function to check crt.sh for certificates
check_crtsh() {
    echo "Checking crt.sh for certificates related to $DOMAIN..."
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u > $CRT_FILE
    echo -e "
============================ CRT.SH CERTIFICATES ============================
" >> dns_table.txt
    while read -r cert_subdomain; do
        echo -e "CRT.SH	$cert_subdomain	Found in Certificate Transparency logs" >> dns_table.txt
    done < $CRT_FILE
}


# Query important DNS record types for the main domain
echo "Gathering DNS records for $DOMAIN..."
for record_type in A CNAME MX TXT NS SOA AAAA; do
    query_dns $DOMAIN $record_type
done

# Test each nameserver for zone transfer
dig $DOMAIN NS +short | while read -r ns; do
    check_axfr $ns
done

# Subdomain enumeration using subfinder
echo "Enumerating subdomains..."
subfinder -d $DOMAIN -silent > $SUBDOMAINS_FILE

# Brute force subdomain enumeration
brute_force_subdomains() {
    echo "Starting subdomain brute force enumeration..."
    while read -r sub; do
        subdomain="$sub.$DOMAIN"
        if dig $subdomain A +short &>/dev/null; then
            echo "Discovered subdomain: $subdomain"
            echo -e "BRUTE\t$subdomain\t" >> dns_table.txt
            query_dns $subdomain A
        fi
    done < subdomains_wordlist.txt
}

# Call brute force subdomain enumeration if wordlist exists
if [ -f subdomains_wordlist.txt ]; then
    brute_force_subdomains
fi

# Check DNS for each discovered subdomain
while read -r subdomain; do
    echo "Gathering DNS records for subdomain: $subdomain"

    # Separator for subdomain clarity
    echo -e "\n============================ $subdomain ============================\n" >> dns_table.txt

    # Query DNS records for each subdomain
    for record_type in A CNAME MX TXT; do
        query_dns $subdomain $record_type
    done

    # Perform reverse DNS lookup for each IP address associated with the subdomain
    dig $subdomain A +short | while read -r ip; do
        reverse_dns $ip
    done
done < $SUBDOMAINS_FILE

# Check crt.sh for certificate transparency logs
check_crtsh

# Get WHOIS data for the domain
echo "Retrieving WHOIS data for $DOMAIN..."
whois $DOMAIN > $WHOIS_FILE

# Append WHOIS data to the report
echo -e "\n\nWHOIS INFORMATION FOR $DOMAIN:\n" >> dns_table.txt
cat $WHOIS_FILE >> dns_table.txt

# Append DNS record type explanations to the bottom of the report
echo -e "\n\nDNS RECORD TYPE EXPLANATIONS:" >> dns_table.txt
echo -e "A:\tMaps a domain to an IP address (IPv4)" >> dns_table.txt
echo -e "AAAA:\tMaps a domain to an IP address (IPv6)" >> dns_table.txt
echo -e "CNAME:\tAlias of one domain to another" >> dns_table.txt
echo -e "MX:\tMail exchange record that routes email to mail servers" >> dns_table.txt
echo -e "TXT:\tProvides text information to sources outside your domain" >> dns_table.txt
echo -e "NS:\tSpecifies the name servers for a domain" >> dns_table.txt
echo -e "SOA:\tStart of Authority, holds administrative information about the domain" >> dns_table.txt
echo -e "PTR:\tMaps an IP address to a domain name (Reverse DNS)" >> dns_table.txt

echo "BRUTE:\tIndicates subdomains discovered through brute-force" >> dns_table.txt
echo "CRT.SH:\tSubdomains found in Certificate Transparency logs" >> dns_table.txt

# Display the final DNS audit table
echo "DNS audit completed. Here are the results:"
column -t -s $'\t' dns_table.txt

# Clean up temporary files
rm -f $DNS_RECORDS_FILE $WHOIS_FILE $SUBDOMAINS_FILE $CRT_FILE


echo "Completed. Step 2 run the command below."
echo "sudo nmap -Pn -sV --top-ports 1000 -A --script vulners,http-enum,ssl-enum-ciphers dvfriends.org_nmap.txt"
echo "sudo nikto -h dvfriends.org"