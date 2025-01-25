import os

# AdGuardHome credentials
# TODO: shouldn't be cleartext
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD")

# Change this to your AdGuard Home instance URL
ADGUARD_URL = os.environ.get("ADGUARD_URL", default='https://192.168.0.30:443')

# Set to False if you use HTTPS on the web interface without a valid certificate
ADGUARD_SSL_VERIFY = os.environ.get("ADGUARD_SSL_VERIFY", default=False)

# File containing domains to monitor
# Should be an absolute path if the file is somewhere else
PAUSERS_FILE = os.environ.get("PAUSERS_FILE", default='pausers.txt')

# Whenever to match all subdomains of the targeted domains as well
# Set to False if you only want to pause when exact domains are accessed
PAUSERS_SUBDOMAINS = os.environ.get("PAUSERS_SUBDOMAINS", default=True)

# AdGuardHome protection pause duration in minutes
PAUSE_DURATION = os.environ.get("PAUSE_DURATION", default=5)

# Pause protection for the whole network, or only for the client that accessed the domain
# The client option is experimental
PAUSE_TYPE = os.environ.get("PAUSE_TYPE", default='client')

# How often to poll query log from the server in seconds
QUERY_INTERVAL = os.environ.get("QUERY_INTERVAL", default=5)

# How many recent queries should be requested from the server
# Should be increased if you process a lot of queries per second (ex. on large networks)
# Higher limit = Higher load on the server CPU
QUERY_LIMIT = os.environ.get("QUERY_LIMIT", default=15)

# Required freshness of the processed queries in seconds
# Don't modify unless needed. Should NOT be higher than QUERY_INTERVAL
QUERY_FRESHNESS = os.environ.get("QUERY_FRESHNESS", default=QUERY_INTERVAL)
