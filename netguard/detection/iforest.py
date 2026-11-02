import json
import math
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from netguard.config import load_config
from netguard.db import DEFAULT_DB_PATH, get_db, init_db
from netguard.detection.base import Finding, get_suggested_precautions

FEATURE_NAMES = [
    "unique_dst_ports",
    "unique_dst_ips",
    "failed_flow_ratio",
    "max_flows_same_target",
    "dns_query_count",
    "avg_qname_length",
    "nxdomain_ratio",
    "bytes_out_external",
    "out_in_ratio",
]

FAMILY_MAPPING = {
    "unique_dst_ports": "Scan",
    "unique_dst_ips": "Scan",
    "failed_flow_ratio": "Scan",
    "max_flows_same_target": "Brute-force",
    "dns_query_count": "DNS",
    "avg_qname_length": "DNS",
    "nxdomain_ratio": "DNS",
    "bytes_out_external": "Outbound",
    "out_in_ratio": "Outbound",
}

STAGE_MAPPING = {
    "Scan": "Reconnaissance",
    "Brute-force": "Access Attempt",
    "DNS": "Possible Exploitation",
    "Outbound": "Possible Exfiltration",
    "Unclassified": "Unclassified",
}

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "models"


def get_models_dir() -> Path:
    """
    Resolve the model directory at call time. NETGUARD_MODELS_DIR overrides the default so
    that tests (and experiments) never write into the production data/models directory.
    """
    override = os.environ.get("NETGUARD_MODELS_DIR")
    return Path(override) if override else MODELS_DIR


def find_model_id(
    model_path: Union[str, Path],
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    model_name: Optional[str] = None,
) -> Optional[int]:
    """
    Return the id of the most recent models-table row registered in db_path for this model.
    Returns None if the model is not registered in db_path (preserving foreign-key integrity).
    """
    try:
        conn = get_db(db_path)
        try:
            if model_path:
                row = conn.execute(
                    "SELECT id FROM models WHERE model_path = ? ORDER BY id DESC LIMIT 1;",
                    (str(Path(model_path)),),
                ).fetchone()
                if row:
                    return int(row["id"])
            if model_name:
                row = conn.execute(
                    "SELECT id FROM models WHERE name = ? ORDER BY id DESC LIMIT 1;",
                    (str(model_name),),
                ).fetchone()
                if row:
                    return int(row["id"])
            return None
        finally:
            conn.close()
    except Exception:
        return None


def rows_to_feature_matrix(feature_rows: List[Dict[str, Any]]) -> np.ndarray:
    """
    Convert list of feature dictionaries into numpy array of shape (N, 9).
    """
    matrix = []
    for r in feature_rows:
        row_vals = [float(r.get(feat, 0.0)) for feat in FEATURE_NAMES]
        matrix.append(row_vals)
    return np.array(matrix, dtype=np.float64)


def train_baseline_model(
    baseline_rows: List[Dict[str, Any]],
    calibration_rows: Optional[List[Dict[str, Any]]] = None,
    model_name: str = "default_baseline",
    baseline_sha256s: Optional[List[str]] = None,
    config: Optional[Dict[str, Any]] = None,
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Train Isolation Forest model on benign baseline feature rows.
    Requires minimum baseline windows (default 50).
    Calibrates anomaly score threshold at the 99th percentile using a separate
    calibration dataset if provided (otherwise on training baseline).
    Saves model joblib bundle and returns metadata dictionary.
    """
    if config is None:
        config = load_config()

    ml_config = config.get("ml", {})
    min_baseline_windows = int(ml_config.get("min_baseline_windows", 50))
    threshold_percentile = float(ml_config.get("threshold_percentile", 99.0))
    seed = int(config.get("general", {}).get("seed", 42))
    window_seconds = int(config.get("general", {}).get("window_seconds", 20))

    if len(baseline_rows) < min_baseline_windows:
        raise ValueError(
            f"Capture more normal traffic or use a shorter window. "
            f"Baseline has {len(baseline_rows)} host-window rows, minimum required is {min_baseline_windows}."
        )

    X_raw = rows_to_feature_matrix(baseline_rows)
    N = X_raw.shape[0]

    # Ensure zero-variance baseline feature columns have small deterministic spread
    for col in range(X_raw.shape[1]):
        if float(np.ptp(X_raw[:, col])) == 0.0:
            base_val = float(X_raw[0, col])
            delta = max(base_val * 0.05, 0.01)
            X_raw[:, col] = base_val + delta * np.sin(np.arange(N, dtype=np.float64))

    X_log = np.log1p(X_raw)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_log)

    model = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination="auto",
        random_state=seed,
    )
    model.fit(X_scaled)

    # Threshold calibration: use separate calibration set if provided
    if calibration_rows and len(calibration_rows) > 0:
        X_calib_raw = rows_to_feature_matrix(calibration_rows)
        X_calib_log = np.log1p(X_calib_raw)
        X_calib_scaled = scaler.transform(X_calib_log)
        calib_scores = -model.score_samples(X_calib_scaled)
        threshold = float(np.percentile(calib_scores, threshold_percentile))
        n_calib = len(calibration_rows)
    else:
        baseline_scores = -model.score_samples(X_scaled)
        threshold = float(np.percentile(baseline_scores, threshold_percentile))
        n_calib = 0

    # Calculate baseline stats (median and 95th percentile per feature)
    baseline_stats = {}
    for idx, name in enumerate(FEATURE_NAMES):
        vals = X_raw[:, idx]
        baseline_stats[name] = {
            "median": float(np.median(vals)),
            "p95": float(np.percentile(vals, 95)),
        }

    models_dir = get_models_dir()
    models_dir.mkdir(parents=True, exist_ok=True)
    joblib_path = models_dir / f"{model_name}.joblib"
    trained_at = time.time()

    bundle = {
        "scaler": scaler,
        "model": model,
        "threshold": threshold,
        "threshold_percentile": threshold_percentile,
        "window_seconds": window_seconds,
        "feature_list": FEATURE_NAMES,
        "baseline_stats": baseline_stats,
        "seed": seed,
        "model_version": "1.1.0",
        "n_train_rows": len(baseline_rows),
        "n_calib_rows": n_calib,
        "trained_at": trained_at,
        "baseline_sha256s": list(baseline_sha256s or []),
        "provenance": dict(provenance or {}),
    }
    joblib.dump(bundle, joblib_path)

    # Persist metadata to models table
    import sklearn

    init_db(db_path)
    conn = get_db(db_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO models (
                name, model_path, baseline_sha256s_json, window_seconds,
                feature_list_json, n_train_rows, threshold, threshold_percentile,
                baseline_stats_json, params_json, seed, sklearn_version, trained_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                model_name,
                str(joblib_path),
                json.dumps(baseline_sha256s or []),
                window_seconds,
                json.dumps(FEATURE_NAMES),
                len(baseline_rows),
                threshold,
                threshold_percentile,
                json.dumps(baseline_stats),
                json.dumps({
                    "n_estimators": 100,
                    "random_state": seed,
                    "model_version": "1.1.0",
                    "n_calib_rows": n_calib,
                    "provenance": dict(provenance or {}),
                }),
                seed,
                getattr(sklearn, "__version__", "unknown"),
                trained_at,
            ),
        )
        model_id = cursor.lastrowid
        conn.commit()
        bundle["model_id"] = model_id
        joblib.dump(bundle, joblib_path)
        return bundle
    finally:
        conn.close()


def load_model_bundle(model_path_or_name: Union[str, Path]) -> Dict[str, Any]:
    """
    Load saved Isolation Forest joblib bundle.
    """
    path = Path(model_path_or_name)
    if not path.exists():
        path = get_models_dir() / f"{model_path_or_name}.joblib"

    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {path}")

    bundle = joblib.load(path)
    bundle.setdefault("model_path", str(path))
    return bundle


def score_windows_with_model(
    feature_rows: List[Dict[str, Any]],
    model_bundle: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Finding], List[Dict[str, Any]]]:
    """
    Score test feature rows with trained Isolation Forest model bundle.
    Flags windows where anomaly score > calibrated threshold.
    Returns (findings_list, updated_feature_rows).
    """
    if config is None:
        config = load_config()

    if not feature_rows:
        return [], []

    ml_config = config.get("ml", {})
    top_features_count = int(ml_config.get("top_features", 3))
    family_min_z = float(ml_config.get("family_min_z", 2.0))
    window_seconds = float(config.get("general", {}).get("window_seconds", 20))

    scaler: StandardScaler = model_bundle["scaler"]
    model: IsolationForest = model_bundle["model"]
    threshold: float = float(model_bundle["threshold"])
    baseline_stats: Dict[str, Any] = model_bundle.get("baseline_stats", {})

    X_raw = rows_to_feature_matrix(feature_rows)
    X_log = np.log1p(X_raw)
    X_scaled = scaler.transform(X_log)

    scores = -model.score_samples(X_scaled)

    findings: List[Finding] = []

    for idx, row in enumerate(feature_rows):
        score = float(scores[idx])
        is_flagged = score > threshold

        row["if_score"] = round(score, 6)
        row["if_flag"] = 1 if is_flagged else 0

        if is_flagged:
            # z-scores per feature
            z_scores = X_scaled[idx]

            # Collect feature deviations
            feature_deviations = []
            family_z_scores: Dict[str, float] = {}

            for f_idx, feat_name in enumerate(FEATURE_NAMES):
                z_val = float(z_scores[f_idx])
                raw_val = float(X_raw[idx, f_idx])
                fam = FAMILY_MAPPING.get(feat_name, "Unclassified")

                if fam not in family_z_scores or z_val > family_z_scores[fam]:
                    family_z_scores[fam] = z_val

                feature_deviations.append(
                    {
                        "feature": feat_name,
                        "raw_value": raw_val,
                        "z_score": round(z_val, 4),
                        "family": fam,
                        "baseline_median": baseline_stats.get(feat_name, {}).get("median", 0.0),
                    }
                )

            # Sort by highest positive z-score
            feature_deviations.sort(key=lambda item: item["z_score"], reverse=True)
            top_deviations = feature_deviations[:top_features_count]

            # Dominant family determination
            dominant_fam = max(family_z_scores.keys(), key=lambda k: family_z_scores[k]) if family_z_scores else "Unclassified"
            if family_z_scores.get(dominant_fam, 0.0) < family_min_z:
                dominant_fam = "Unclassified"

            stage = STAGE_MAPPING.get(dominant_fam, "Unclassified")

            # Severity offset calculation
            medium_offset = float(ml_config.get("severity_offsets", {}).get("medium", 0.05))
            high_offset = float(ml_config.get("severity_offsets", {}).get("high", 0.10))

            if score >= threshold + high_offset:
                severity = "high"
            elif score >= threshold + medium_offset:
                severity = "medium"
            else:
                severity = "low"

            row["top_features_json"] = json.dumps(
                {"dominant_family": dominant_fam, "top_features": top_deviations}
            )

            top_feat_strs = [
                f"{d['feature']} (largest deviation: z={d['z_score']:.1f}, baseline median {d['baseline_median']})"
                for d in top_deviations
            ]
            summary = (
                f"Host {row['host_ip']} behaved unlike the baseline "
                f"(score {score:.2f}, threshold {threshold:.2f}). "
                f"Largest deviations from baseline: {', '.join(top_feat_strs)}. "
                f"Dominant family: {dominant_fam.lower()}."
            )

            first_frame = row.get("first_frame", 1)
            last_frame = row.get("last_frame", 1)

            details = {
                "score": round(score, 4),
                "threshold": round(threshold, 4),
                "dominant_family": dominant_fam,
                "top_features": top_deviations,
                "first_frame": first_frame,
                "last_frame": last_frame,
                "suggested_precautions": get_suggested_precautions("ml_anomaly"),
            }

            finding = Finding(
                alert_type="ml_anomaly",
                detector="iforest",
                rule_name="iforest_host_anomaly",
                severity=severity,
                confidence=0.5,
                src_ip=row["host_ip"],
                dst_ip=None,
                dst_port=None,
                start_ts=float(row["window_start"]),
                end_ts=float(row["window_end"]),
                stage=stage,
                summary=summary,
                details=details,
                evidence_refs=[
                    {
                        "ref_type": "window",
                        "ref_id": row.get("id", 0),
                        "frame_no": first_frame,
                        "note": f"ML host anomaly window (score: {score:.2f}, threshold: {threshold:.2f})",
                    }
                ],
            )
            findings.append(finding)

    return findings, feature_rows
