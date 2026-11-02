import pytest
import sqlite3
import numpy as np
from pathlib import Path
from netguard.config import load_config
from netguard.detection.iforest import (
    train_baseline_model,
    load_model_bundle,
    score_windows_with_model,
    FEATURE_NAMES,
)
from tests.test_iforest import make_feature_row


def test_train_with_separate_calibration(tmp_path):
    """
    Verify training baseline on train_rows and calibrating 99th percentile
    on a separate calibration_rows set without leakage.
    """
    config = load_config()
    db_path = tmp_path / "test_ml_calib.db"

    # 60 benign training windows
    train_rows = [make_feature_row(window_start=i * 20.0, bytes_out_external=1000 + i) for i in range(60)]
    # 25 separate calibration windows
    calib_rows = [make_feature_row(window_start=5000.0 + i * 20.0, bytes_out_external=1100 + i) for i in range(25)]

    bundle = train_baseline_model(
        baseline_rows=train_rows,
        calibration_rows=calib_rows,
        model_name="test_calib_model",
        config=config,
        db_path=db_path,
    )

    assert bundle["model_version"] == "1.1.0"
    assert bundle["n_train_rows"] == 60
    assert bundle["n_calib_rows"] == 25
    assert bundle["threshold"] > 0.0

    # Ensure metadata recorded in DB
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT * FROM models WHERE name = 'test_calib_model';").fetchone()
    conn.close()
    assert row is not None


def test_schema_mismatch_fails_cleanly(tmp_path):
    """
    Verify feature schema mismatch or missing keys handle gracefully.
    """
    config = load_config()
    db_path = tmp_path / "test_ml_schema.db"
    train_rows = [make_feature_row(window_start=i * 20.0) for i in range(55)]
    bundle = train_baseline_model(train_rows, model_name="test_schema", config=config, db_path=db_path)

    # Incomplete test row missing critical features defaults to 0.0 without crash
    incomplete_row = [{"host_ip": "10.0.0.1", "window_start": 100.0, "window_end": 120.0}]
    findings, updated = score_windows_with_model(incomplete_row, bundle, config=config)
    assert len(updated) == 1
    assert updated[0]["if_score"] is not None


def test_model_persistence_and_reload(tmp_path):
    """
    Verify loaded bundle produces identical score_samples and decisions to original.
    """
    config = load_config()
    db_path = tmp_path / "test_persist.db"
    train_rows = [make_feature_row(window_start=i * 20.0) for i in range(60)]
    bundle1 = train_baseline_model(train_rows, model_name="test_persist", config=config, db_path=db_path)

    bundle2 = load_model_bundle("test_persist")
    assert bundle1["threshold"] == bundle2["threshold"]

    test_row = [make_feature_row(window_start=9999.0, unique_dst_ports=50)]
    f1, u1 = score_windows_with_model(test_row, bundle1, config=config)
    f2, u2 = score_windows_with_model(test_row, bundle2, config=config)

    assert u1[0]["if_score"] == u2[0]["if_score"]
    assert len(f1) == len(f2)


def test_held_out_evaluation_metrics(tmp_path):
    """
    Verify false alert calculation on benign traffic vs anomalous outlier.
    """
    config = load_config()
    db_path = tmp_path / "test_eval.db"
    train_rows = [make_feature_row(window_start=i * 20.0) for i in range(60)]
    calib_rows = [make_feature_row(window_start=2000.0 + i * 20.0) for i in range(30)]
    bundle = train_baseline_model(
        baseline_rows=train_rows,
        calibration_rows=calib_rows,
        model_name="test_eval",
        config=config,
        db_path=db_path,
    )

    # 40 benign held-out test windows
    test_rows = [make_feature_row(window_start=4000.0 + i * 20.0) for i in range(40)]
    findings, _ = score_windows_with_model(test_rows, bundle, config=config)

    # False alert count should be very low (close to 1-5% for 99th percentile)
    assert len(findings) <= 4


def test_run_analysis_persists_if_score_and_model_id(tmp_path):
    """
    Verify run_analysis persists if_score, if_flag, top_features_json into feature_windows
    and links runs.model_id to the registered models row.
    """
    from netguard.pipeline import import_capture, run_analysis

    config = load_config()
    db_path = tmp_path / "test_pipeline_ml.db"
    train_rows = [make_feature_row(window_start=i * 20.0) for i in range(60)]
    calib_rows = [make_feature_row(window_start=2000.0 + i * 20.0) for i in range(30)]
    bundle = train_baseline_model(
        baseline_rows=train_rows,
        calibration_rows=calib_rows,
        model_name="default_baseline",
        config=config,
        db_path=db_path,
    )

    pcap_path = Path(__file__).resolve().parent / "data" / "pcaps" / "brute_force.pcap"
    cap = import_capture(pcap_path, db_path=db_path, config=config)
    res = run_analysis(cap["id"], db_path=db_path, config=config, model_name="default_baseline")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    run_row = conn.execute("SELECT * FROM runs WHERE id = ?;", (res["run_id"],)).fetchone()
    assert run_row["model_id"] == bundle["model_id"]

    fw_rows = conn.execute("SELECT * FROM feature_windows WHERE run_id = ? ORDER BY host_ip;", (res["run_id"],)).fetchall()
    conn.close()
    assert len(fw_rows) == 2
    for fw in fw_rows:
        assert fw["if_score"] is not None
        assert fw["if_score"] > 0.0


