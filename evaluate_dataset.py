#!/usr/bin/env python
"""
NetGuard Dataset Evaluation & Benchmarking CLI
Runs evaluation against authentic intrusion detection datasets (CIC-IDS2017, UNSW-NB15).
Outputs confusion matrix, precision, recall, F1, false positive rate, and throughput.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from netguard.datasets.benchmark import DATASET_REGISTRY, evaluate_csv_dataset


def main():
    parser = argparse.ArgumentParser(description="NetGuard Authentic Dataset Benchmarking Utility")
    parser.add_argument(
        "--csv",
        type=str,
        default=str(PROJECT_ROOT / "tests" / "data" / "datasets" / "cic_ids2017_sample.csv"),
        help="Path to labeled benchmark CSV dataset",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="CIC-IDS2017",
        choices=["CIC-IDS2017", "UNSW-NB15"],
        help="Target dataset profile",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Optional row limit for large CSV benchmarks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON results",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"Error: Dataset CSV file not found at {csv_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 72)
    print(f"       NETGUARD AUTHENTIC DATASET BENCHMARK: {args.dataset}")
    print("=" * 72)
    meta = DATASET_REGISTRY.get(args.dataset)
    if meta:
        print(f"Institution : {meta.institution}")
        print(f"License     : {meta.license}")
        print(f"Reference   : {meta.official_url}")
    print("-" * 72)
    print(f"Evaluating {csv_path.name}...")

    results = evaluate_csv_dataset(csv_path, dataset_name=args.dataset, max_rows=args.max_rows)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    m = results["metrics"]
    cm = results["confusion_matrix"]

    print("\n--- PERFORMANCE METRICS ---")
    print(f"Total Evaluated Flows : {results['total_flows']:,}")
    print(f"Benchmark Duration    : {results['elapsed_seconds']}s ({results['throughput_fps']} flows/sec)")
    print(f"Accuracy              : {m['accuracy'] * 100:.2f}%")
    print(f"Precision             : {m['precision'] * 100:.2f}%")
    print(f"Recall (Sensitivity)  : {m['recall'] * 100:.2f}%")
    print(f"F1-Score              : {m['f1_score']:.4f}")
    print(f"False Positive Rate   : {m['false_positive_rate'] * 100:.2f}%")

    print("\n--- CONFUSION MATRIX ---")
    print("                Predicted Negative | Predicted Positive")
    print(f"Actual Negative: {cm['TN']:<17} | {cm['FP']:<17} (True Negatives / False Positives)")
    print(f"Actual Positive: {cm['FN']:<17} | {cm['TP']:<17} (False Negatives / True Positives)")

    print("\n--- ATTACK CLASS BREAKDOWN ---")
    print(f"{'Attack Class':<20} | {'Total':<8} | {'Detected':<8} | {'Detection Rate'}")
    print("-" * 55)
    for cls_name, stats in results["attack_breakdown"].items():
        tot = stats["total"]
        det = stats["detected"]
        rate = f"{(det / tot) * 100:.1f}%" if tot > 0 else "N/A"
        print(f"{cls_name:<20} | {tot:<8} | {det:<8} | {rate}")

    print("=" * 72)


if __name__ == "__main__":
    main()
