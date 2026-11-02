"""
Ingestion module for NetGuard.
"""

from netguard.ingest.pcap_reader import parse_pcap_stream, calculate_sha256

__all__ = ["parse_pcap_stream", "calculate_sha256"]
