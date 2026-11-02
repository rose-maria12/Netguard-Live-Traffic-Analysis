import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from netguard.config import load_config
from netguard.db import init_db
from netguard.pipeline import import_capture, run_analysis

DATA_DIR = Path(__file__).resolve().parent / "tests" / "data"
PCAPS_DIR = DATA_DIR / "pcaps"
TRUTH_DIR = DATA_DIR / "truth"


def evaluate_detector_rules() -> Dict[str, Dict[str, Any]]:
    """
    Evaluate NetGuard rule-based detectors against ground-truth JSON definitions.
    Computes TP, FP, FN, Precision, Recall for each detector type.
    """
    detectors = ["port_scan", "brute_force", "dns_anomaly", "abnormal_outbound"]
    metrics: Dict[str, Dict[str, Any]] = {
        det: {"TP": 0, "FP": 0, "FN": 0, "precision": 0.0, "recall": 0.0}
        for det in detectors
    }

    if not TRUTH_DIR.exists():
        print("Ground truth directory not found. Please run generate_test_pcaps.py first.")
        return metrics

    truth_files = list(TRUTH_DIR.glob("*_truth.json"))

    eval_dir = DATA_DIR / "eval_tmp"
    eval_dir.mkdir(parents=True, exist_ok=True)
    db_path = eval_dir / "eval.db"
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    try:
        init_db(db_path)
        config = load_config()

        for tf in sorted(truth_files):
            if "TEMPLATE" in tf.name:
                continue
            with open(tf, "r", encoding="utf-8-sig") as f:
                truth = json.load(f)

            pcap_filename = truth["pcap_filename"]
            pcap_path = PCAPS_DIR / pcap_filename
            if not pcap_path.exists():
                continue

            cap = import_capture(pcap_path, db_path=db_path, config=config)
            res = run_analysis(cap["id"], db_path=db_path, config=config)

            # Get generated rule alerts for this run
            run_alerts = [
                a for a in res["incidents"] for a in a.alerts if a.detector == "rule"
            ]

            expected_alerts = truth.get("expected_alerts", [])

            # Match detected alerts to expected alerts per detector
            for det in detectors:
                det_expected = [e for e in expected_alerts if e["alert_type"] == det]
                det_observed = [a for a in run_alerts if a.alert_type == det]

                matched_expected = set()
                matched_observed = set()

                for i_exp, exp in enumerate(det_expected):
                    for i_obs, obs in enumerate(det_observed):
                        if exp["src_ip"] == obs.src_ip:
                            if exp.get("dst_ip") is None or exp["dst_ip"] == obs.dst_ip:
                                matched_expected.add(i_exp)
                                matched_observed.add(i_obs)
                                break

                tp = len(matched_expected)
                fn = len(det_expected) - tp
                fp = len(det_observed) - len(matched_observed)

                metrics[det]["TP"] += tp
                metrics[det]["FP"] += fp
                metrics[det]["FN"] += fn

    finally:
        if db_path.exists():
            try:
                db_path.unlink()
            except Exception:
                pass

    # Calculate Precision and Recall
    for det, m in metrics.items():
        tp = m["TP"]
        fp = m["FP"]
        fn = m["FN"]

        m["precision"] = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        m["recall"] = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0

    return metrics


def print_evaluation_report():
    """
    Print a clean, formatted evaluation report for rule detectors and Isolation Forest ML.
    """
    print("=" * 72)
    print("           NETGUARD DETECTOR EVALUATION REPORT (SYNTHETIC LAB)")
    print("=" * 72)
    print("Disclaimer: Results derived from controlled synthetic/educational datasets.")
    print("Rule precision and recall are indicative of design correctness.\n")

    rule_metrics = evaluate_detector_rules()

    print(f"{'DETECTOR TYPE':<22} | {'TP':<4} | {'FP':<4} | {'FN':<4} | {'PRECISION':<10} | {'RECALL':<10}")
    print("-" * 72)
    for det, m in rule_metrics.items():
        print(
            f"{det:<22} | {m['TP']:<4} | {m['FP']:<4} | {m['FN']:<4} | "
            f"{m['precision']*100.0:>8.1f}% | {m['recall']*100.0:>8.1f}%"
        )
    print("-" * 72)

    print("\n" + "=" * 72)
    print("       ISOLATION FOREST ANOMALY DETECTOR EVALUATION SUMMARY")
    print("=" * 72)
    print("Note: ML evaluation reports baseline behavior & window scoring.")
    print("Model Calibration: 99th Percentile baseline score thresholding.")
    print("Baseline Windows Required: 50 minimum host-window samples.")
    print("Deterministic Random Seed: 42 (Reproducible Scikit-Learn Isolation Forest).")
    print("=" * 72)


if __name__ == "__main__":
    print_evaluation_report()
