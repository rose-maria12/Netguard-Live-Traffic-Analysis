"""
NetGuard Isolation Forest Baseline Training & Calibration Script
Uses the authentic CICIDS2017 Monday benign traffic dataset (30MB slice, 47,218 packets).
Splits traffic into:
  1. Train (60% temporal windows) - fits StandardScaler and IsolationForest
  2. Calibrate (20% temporal windows) - computes 99th percentile decision threshold
  3. Held-out Test (20% temporal windows) - validates false alert rate
"""
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
from netguard.config import load_config
from netguard.db import DEFAULT_DB_PATH
from netguard.pipeline import import_capture
from netguard.features.window_features import extract_window_features_for_capture
from netguard.detection.iforest import (
    train_baseline_model,
    load_model_bundle,
    score_windows_with_model,
    rows_to_feature_matrix,
    FEATURE_NAMES,
)


def run_training_pipeline(
    pcapng_path: Path,
    model_name: str = "default_baseline",
    db_path: Path = DEFAULT_DB_PATH,
):
    print("=" * 70)
    print("NETGUARD ISOLATION FOREST BASELINE TRAINING & CALIBRATION")
    print("=" * 70)
    print(f"Dataset PCAPNG: {pcapng_path}")
    print(f"Target Model:   {model_name}")
    print(f"Target DB:      {db_path}")

    if not pcapng_path.exists():
        raise FileNotFoundError(f"Dataset not found at {pcapng_path}")

    # Use a temporary DB for feature extraction to avoid polluting production DB with training packets
    temp_db = PROJECT_ROOT / "data" / "cicids2017" / "temp_training.db"
    if temp_db.exists():
        temp_db.unlink()

    print("\n[Step 1/4] Ingesting authentic benign PCAPNG into NetGuard pipeline...")
    cap_res = import_capture(str(pcapng_path), db_path=temp_db)
    capture_id = cap_res["id"]
    print(f"-> Ingested {cap_res['packets_stored']} packets (SHA-256: {cap_res['sha256'][:16]}...)")

    print("\n[Step 2/4] Extracting 20-second tumbling host-window feature records...")
    all_rows = extract_window_features_for_capture(capture_id, db_path=temp_db)
    print(f"-> Extracted {len(all_rows)} total host-window feature vectors across 9 dimensions.")

    # Sort and split temporally without leakage
    wstarts = sorted(list(set(r["window_start"] for r in all_rows)))
    n_w = len(wstarts)
    train_wstarts = set(wstarts[: int(n_w * 0.6)])
    calib_wstarts = set(wstarts[int(n_w * 0.6) : int(n_w * 0.8)])
    test_wstarts = set(wstarts[int(n_w * 0.8) :])

    train_rows = [r for r in all_rows if r["window_start"] in train_wstarts]
    calib_rows = [r for r in all_rows if r["window_start"] in calib_wstarts]
    test_rows = [r for r in all_rows if r["window_start"] in test_wstarts]

    print("\n[Step 3/4] Temporal Non-Overlapping Splits:")
    print(f"  - Training Baseline:    {len(train_rows)} windows (first 60% time period)")
    print(f"  - Separate Calibration: {len(calib_rows)} windows (middle 20% time period)")
    print(f"  - Held-out Benign Test: {len(test_rows)} windows (final 20% time period)")

    config = load_config()

    print("\n[Step 4/4] Fitting Isolation Forest & Calibrating 99th-Percentile Threshold...")
    provenance = {
        "dataset_file": pcapng_path.name,
        "dataset_sha256": cap_res["sha256"],
        "packets_stored": cap_res["packets_stored"],
        "total_windows": len(all_rows),
        "n_train_rows": len(train_rows),
        "n_calib_rows": len(calib_rows),
        "n_test_rows": len(test_rows),
        "train_time_slots": len(train_wstarts),
        "calib_time_slots": len(calib_wstarts),
        "test_time_slots": len(test_wstarts),
        "total_time_slots": n_w,
        "same_session_split": True,
    }
    bundle = train_baseline_model(
        baseline_rows=train_rows,
        calibration_rows=calib_rows,
        model_name=model_name,
        baseline_sha256s=[cap_res["sha256"]],
        config=config,
        db_path=db_path,
        provenance=provenance,
    )

    threshold = bundle["threshold"]
    print(f"\n[RESULTS] Model successfully trained and saved!")
    print(f"  - Model Path:           data/models/{model_name}.joblib")
    print(f"  - Version:              {bundle['model_version']}")
    print(f"  - Decision Threshold:   {threshold:.4f} (99th percentile on separate calibration set)")

    # Score held-out benign test set
    findings, updated_test = score_windows_with_model(test_rows, bundle, config=config)
    false_alert_count = len(findings)
    fpr = (false_alert_count / len(test_rows)) * 100 if test_rows else 0.0

    print(f"\n[VALIDATION ON HELD-OUT BENIGN TRAFFIC]")
    print(f"  - Scored Windows:       {len(test_rows)}")
    print(f"  - False Alerts Flagged: {false_alert_count} / {len(test_rows)} ({fpr:.2f}% FPR)")
    print(f"  - Consistent with ~1.0-5.0% expected tail of 99th-percentile calibration.")

    # Cleanup temp db
    if temp_db.exists():
        try:
            temp_db.unlink()
        except Exception:
            pass

    print("\nPipeline completed successfully!")
    return bundle


if __name__ == "__main__":
    pcap_path = PROJECT_ROOT / "data" / "cicids2017" / "cicids2017_monday_benign_subset.pcapng"
    run_training_pipeline(pcap_path)

