#!/usr/bin/env python3
"""
Threat Intel Enrichment Script.
Checks file hashes and IPs against VirusTotal and AbuseIPDB.
Designed to be called by Wazuh Active Response or run manually.
This script queries multiple Threat Intelligence Platforms (TIPs) for IOCs found on the endpoint
"""

import argparse
import json
import os
import sys
from pathlib import Path
import requests

# Configuration - Load from environment variables or a config file in a real setup
VT_API_KEY = os.getenv('VT_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'YOUR_ABUSEIPDB_API_KEY')

def query_virustotal(file_hash):
    """Query VirusTotal for a file hash."""
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VT_API_KEY, 'resource': file_hash}
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        vt_data = response.json()
        if vt_data['response_code'] == 1:
            return {
                'positives': vt_data['positives'],
                'total': vt_data['total'],
                'permalink': vt_data['permalink']
            }
        else:
            return {'error': 'Hash not found in VirusTotal'}
    except requests.exceptions.RequestException as e:
        return {'error': f'VT API request failed: {str(e)}'}

def query_abuseipdb(ip_address):
    """Query AbuseIPDB for an IP address."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90, 'verbose': ''}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        abuse_data = response.json()
        return {
            'abuseConfidenceScore': abuse_data['data']['abuseConfidenceScore'],
            'countryCode': abuse_data['data']['countryCode'],
            'usageType': abuse_data['data']['usageType'],
            'totalReports': abuse_data['data']['totalReports']
        }
    except requests.exceptions.RequestException as e:
        return {'error': f'AbuseIPDB API request failed: {str(e)}'}

def main():
    parser = argparse.ArgumentParser(description='Threat Intel Enrichment')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--hash', help='File hash (MD5, SHA1, SHA256) to check')
    group.add_argument('--ip', help='IP address to check')

    args = parser.parse_args()

    result = {}
    if args.hash:
        result['virustotal'] = query_virustotal(args.hash)
    elif args.ip:
        result['abuseipdb'] = query_abuseipdb(args.ip)

    # Print result as JSON for easy parsing by Wazuh/other tools
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()