"""
NetGuard AbuseIPDB Threat Intelligence Client
Safely queries AbuseIPDB v2 check endpoint with:
- Environment variable configuration (ABUSEIPDB_API_KEY)
- Private / local / RFC 1918 address safeguards
- In-memory & TTL caching (default 24h)
- Offline fallback and error resilience
- Clear separation: reputation enrichment only, never auto-blocks alone
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400  # 24 hours


class AbuseIPDBClient:
    """
    Client for querying the AbuseIPDB API v2 with rate-limit caching.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "").strip()
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_queryable_public_ip(self, ip_str: str) -> bool:
        """
        Check if an IP is a valid public IPv4/IPv6 address suitable for external lookup.
        Prevents leaking private, loopback, or broadcast internal IPs.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_link_local
                or ip.is_unspecified
            )
        except ValueError:
            return False

    def lookup(self, ip_str: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Lookup reputation for an IP address.
        Returns reputation metrics, or safe offline fallback if unconfigured.
        """
        ip_clean = ip_str.strip()

        # 1. Private/Internal IP check
        if not self.is_queryable_public_ip(ip_clean):
            return {
                "ip": ip_clean,
                "is_public": False,
                "reputation_score": 0,
                "total_reports": 0,
                "country_code": "LOCAL",
                "isp": "Private/Local Network",
                "is_whitelisted": True,
                "source": "local_filter",
                "cached": False,
                "note": "Private or internal IP address. External lookup skipped for privacy.",
            }

        # 2. Cache check
        now = time.time()
        if ip_clean in self._cache:
            entry = self._cache[ip_clean]
            if now - entry["cached_at"] < CACHE_TTL_SECONDS:
                cached_data = dict(entry["data"])
                cached_data["cached"] = True
                return cached_data

        # 3. Check API key
        if not self.api_key:
            return {
                "ip": ip_clean,
                "is_public": True,
                "reputation_score": None,
                "total_reports": 0,
                "country_code": "UNKNOWN",
                "isp": "Unknown",
                "is_whitelisted": None,
                "source": "offline",
                "cached": False,
                "note": "ABUSEIPDB_API_KEY environment variable not configured. Running in offline mode.",
            }

        # 4. Perform HTTP query against AbuseIPDB v2
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip_clean, "maxAgeInDays": max_age_days, "verbose": ""}
        encoded_url = f"{url}?{urllib.parse.urlencode(params)}"

        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
            "User-Agent": "NetGuard-Forensic-Platform/1.0",
        }

        try:
            req = urllib.request.Request(encoded_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8")).get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result = {
                    "ip": ip_clean,
                    "is_public": True,
                    "reputation_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", "UNKNOWN"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", ""),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported_at": data.get("lastReportedAt"),
                    "source": "AbuseIPDB",
                    "cached": False,
                    "note": f"Confidence score: {score}%. Reports: {data.get('totalReports', 0)}.",
                }
                self._cache[ip_clean] = {"data": result, "cached_at": now}
                return result

        except urllib.error.HTTPError as he:
            logger.warning("AbuseIPDB query failed with HTTP %d: %s", he.code, he.reason)
            return {
                "ip": ip_clean,
                "is_public": True,
                "reputation_score": None,
                "total_reports": 0,
                "country_code": "ERROR",
                "isp": "Lookup Failed",
                "source": "error",
                "cached": False,
                "note": f"API request error: HTTP {he.code}",
            }
        except Exception as ex:
            logger.warning("AbuseIPDB lookup exception for %s: %s", ip_clean, ex)
            return {
                "ip": ip_clean,
                "is_public": True,
                "reputation_score": None,
                "total_reports": 0,
                "country_code": "ERROR",
                "isp": "Lookup Failed",
                "source": "error",
                "cached": False,
                "note": f"Network or parsing error: {ex}",
            }


_DEFAULT_CLIENT = AbuseIPDBClient()


def lookup_ip_reputation(ip_str: str) -> Dict[str, Any]:
    """
    Convenience function using singleton client.
    """
    return _DEFAULT_CLIENT.lookup(ip_str)
