"""
NetGuard Dataset Registry & Benchmarking Package
Supports authoritative intrusion detection datasets (CIC-IDS2017, UNSW-NB15)
for both PCAP-level and feature-level forensic evaluation.
"""
from __future__ import annotations

from netguard.datasets.benchmark import (
    DATASET_REGISTRY,
    DatasetMetadata,
    evaluate_csv_dataset,
    evaluate_pcap_dataset,
)

__all__ = [
    "DATASET_REGISTRY",
    "DatasetMetadata",
    "evaluate_csv_dataset",
    "evaluate_pcap_dataset",
]
