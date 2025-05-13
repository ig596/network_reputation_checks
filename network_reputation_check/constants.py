"""Constants for the network reputation check tool."""

from enum import Enum

# ------------------------------------------------------------------------------
# Enum: Supported Source Names
# ------------------------------------------------------------------------------

class Source(str, Enum):
    """Supported reputation check sources."""

    VIRUSTOTAL = "virustotal"
    URLSCAN = "urlscan"

# ------------------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------------------

DEFAULT_SOURCES = [s.value for s in Source]
DEFAULT_OUTPUT_FILE = "results.json"

# ------------------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------------------

# VirusTotal
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# urlscan.io
URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{}"
