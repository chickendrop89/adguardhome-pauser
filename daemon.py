#!/usr/bin/env python3

import time
import json
import logging
import threading
from typing import List
from datetime import datetime, timezone
from pathlib import Path
import requests
import urllib3

# TODO: wildcard import is bad practice
from config import *

if not ADGUARD_USERNAME or not ADGUARD_PASSWORD:
    raise ValueError("AdGuardHome credentials not set in environment variables.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AdGuardHomeClient:
    """API client for interacting with AdGuard Home."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.auth = (username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = ADGUARD_SSL_VERIFY  # SSL certificate verification

        # Disable the urllib warnings if session.verify is False
        urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

    def get(self, endpoint: str, params: dict = None, timeout: int = QUERY_INTERVAL):
        """
        GET request to the AdGuard Home API.
        
        :param endpoint: The API endpoint to send the request to.
        :param params: (optional) Parameters to pass into the request.
        :param timeout: (optional) The request timeout duration in seconds.
        :return: The JSON response data, or None if the request fails.
        """
        try:
            response = self.session.get(f'{self.base_url}/{endpoint}', params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error("Error fetching data from %s: %s", endpoint, e)
            return None

    def post(self, endpoint: str, data: dict, timeout: int = QUERY_INTERVAL):
        """
        POST request to the AdGuard Home API.
        
        :param endpoint: The API endpoint to send the request to.
        :param data: The data payload to include in the request.
        :param timeout: (optional) The request timeout duration in seconds.
        :return: True if the request is successful, otherwise the JSON response data or False.
        """
        try:
            response = self.session.post(f'{self.base_url}/{endpoint}', json=data, timeout=timeout)
            response.raise_for_status()

            if response.status_code != 200:
                return response.json()

            return True
        except requests.exceptions.RequestException as e:
            logging.error("Error posting data to %s: %s", endpoint, e)
            return False

class AdGuardHome:
    """AdGuard Home API wrapper for managing queries and clients."""

    def __init__(self, client: AdGuardHomeClient):
        self.client = client

    def get_dns_block_ttl(self):
        """Get blocked response TTL from AdGuard Home API."""
        data = self.client.get('control/dns_info')
        return data.get('blocked_response_ttl', []) if data else []

    def get_recent_queries(self):
        """Get recent queries from AdGuard Home API."""
        data = self.client.get('control/querylog', params={
            'limit': QUERY_LIMIT,
            'offset': 0
        })
        return data.get('data', []) if data else []

    def check_persistent_client_existence(self, client_ip: str):
        """"Check if a persistent client exists via AdGuard Home API."""
        data = self.client.post('control/clients/search', {
            'clients': [{"id": f"{client_ip}"}]
        })

        # AdGuard Home doesn't provide an API to check existence of persistent client
        # Do this workaround. whois_info appears as a field only when requested non-existing client:
        return "whois_info" not in json.dumps(data) if data else False

    def manage_persistent_client(self, action: str, client_ip: str):
        """
        Manage a persistent client via AdGuard Home API.
        :param action: can be either 'add', 'update' or 'delete'
        """

        endpoint = f'control/clients/{action}'
        data = {
            'add': {
                'name': f'pauser-{client_ip}',
                'use_global_settings': True,
                'ids': [f'{client_ip}']
            },
            'update': {
                'name': f'pauser-{client_ip}',
                'data': {
                    'name': f'pauser-{client_ip}',
                    'filtering_enabled': False, 
                    'ids': [f'{client_ip}']
            }},
            'delete': {
                'name': f'pauser-{client_ip}'
            }
        }.get(action, {})
        return self.client.post(endpoint, data) is not None

    def pause_protection(self, pause_type: str = "network", client_ip: str = None):
        """
        Pause AdGuard Home protection.
        :param pause_type: can be either 'network' or 'client'
        """

        if pause_type == "client" and client_ip:
            # Set a background timer to delete the client after PAUSE_DURATION
            threading.Timer(
                PAUSE_DURATION * 60,  # Convert minutes to seconds
                self.manage_persistent_client, args=['delete', client_ip]
            ).start()

            logging.info("Successfully paused AdGuard Home protection of %s for %s minutes", client_ip, PAUSE_DURATION)
        else:
            # Pause network protection for the specified duration
            if self.client.post('control/protection', {
                'enabled': False,
                'duration': PAUSE_DURATION * 60 * 1000  # Convert minutes to milliseconds
                }):

                logging.info("Successfully paused AdGuard Home protection for %s minutes", PAUSE_DURATION)

        return True

    def check_queries(self, target_domains: List[str]):
        """
        Check query log for recent queries to any target domain.
        :param target_domains: List of domains to monitor.
        """

        current_time = datetime.now(timezone.utc)
        queries = self.get_recent_queries()

        for query in queries:
            query_domain = query['question']['name'].lower()
            matching_domains = [domain for domain in target_domains if domain_matches(query_domain, domain, PAUSERS_SUBDOMAINS)]
            if matching_domains and is_query_fresh(query['time'], current_time, QUERY_FRESHNESS):
                if PAUSERS_SUBDOMAINS:
                    logging.info("Found fresh query for %s matching %s", query_domain, matching_domains[0])
                else:
                    logging.info("Found fresh exact domain match for %s", matching_domains[0])

                if PAUSE_TYPE == 'client':
                    query_client = query['client']

                    if not self.check_persistent_client_existence(query_client):
                        self.manage_persistent_client('add', query_client)

                    self.pause_protection('client', query_client)
                else:
                    self.pause_protection()
                return True

        return False

def load_target_domains(file_path: str):
    """Load target domains from file."""
    try:
        path = Path(file_path)

        if not path.exists():
            logging.warning("Pausers file %s not found. Creating one with example domain", file_path)
            with open(path, 'w', encoding="utf-8") as f:
                f.write("example.com\n")
            return ["example.com"]

        with open(path, 'r', encoding="utf-8") as f:
            domains = [line.strip().lower() for line in f if line.strip()]

        if not domains:
            logging.warning("No domains found in the pausers file. Appending an example domain")
            domains = ["example.com"]
            with open(path, 'w', encoding="utf-8") as f:
                f.write("example.com\n")

        logging.info("Loaded %s domains to monitor: %s", len(domains), ', '.join(domains))
        logging.info("Subdomain matching is %s", 'enabled' if PAUSERS_SUBDOMAINS else 'disabled')
        return domains

    except (PermissionError, OSError) as e:
        logging.error("Error loading domains file: %s", e)
        return ["example.com"]

def parse_timestamp(timestamp_str: str):
    """Parse timestamp string to datetime object."""
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError as e:
        logging.error("Error parsing timestamp: %s", e)
        return None

def is_query_fresh(query_time_str: str, current_time: int, max_age_seconds: int):
    """Check if the query is within the freshness window."""
    query_time = parse_timestamp(query_time_str)

    if query_time is None:
        return False

    if query_time.tzinfo != timezone.utc:
        query_time = query_time.astimezone(timezone.utc)

    time_diff = (current_time - query_time).total_seconds()
    return 0 <= time_diff <= max_age_seconds

def domain_matches(query_domain: str, target_domain: str, allow_subdomains: str):
    """Check if a query domain matches a target domain."""
    if allow_subdomains:
        return query_domain.endswith('.' + target_domain) or query_domain == target_domain
    else:
        return query_domain == target_domain

def main():
    """Main daemon code."""
    logging.info("Starting AdGuard Home query monitor")

    adguard_api_client = AdGuardHomeClient(ADGUARD_URL, ADGUARD_USERNAME, ADGUARD_PASSWORD)
    adguard = AdGuardHome(adguard_api_client)
    adguard_block_ttl = adguard.get_dns_block_ttl()

    if adguard_block_ttl > 120:
        logging.warning("Current block TTL is above 2 minutes! (currently: %ss)", adguard_block_ttl)
        logging.warning("This will minimize the usefulness of the daemon")

    target_domains = load_target_domains(PAUSERS_FILE)
    last_mtime = Path(PAUSERS_FILE).stat().st_mtime

    while True:
        try:
            current_mtime = Path(PAUSERS_FILE).stat().st_mtime
            if current_mtime != last_mtime:
                logging.info("Domains file changed, reloading...")
                target_domains = load_target_domains(PAUSERS_FILE)
                last_mtime = current_mtime

            adguard.check_queries(target_domains)
            time.sleep(QUERY_INTERVAL)

        except KeyboardInterrupt:
            logging.info("Stopping monitor...")
            break
        except (PermissionError, OSError) as e:
            logging.error("Unexpected error: %s", e)
            time.sleep(QUERY_INTERVAL)

if __name__ == "__main__":
    main()