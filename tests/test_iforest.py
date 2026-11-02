import pytest
from netguard.config import load_config
from netguard.detection.iforest import (
    load_model_bundle,
    score_windows_with_model,
    train_baseline_model,
)


def make_feature_row(
    host_ip: str = "192.168.1.10",
    window_start: float = 100.0,
    unique_dst_ports: int = 2,
    unique_dst_ips: int = 2,
    failed_flow_ratio: float = 0.0,
    max_flows_same_target: int = 2,
    dns_query_count: int = 5,
    avg_qname_length: float = 12.0,
    nxdomain_ratio: float = 0.0,
    bytes_out_external: int = 1500,
    out_in_ratio: float = 1.2,
    first_frame: int = 1,
    last_frame: int = 10,
) -> dict:
    return {
        "host_ip": host_ip,
        "window_start": window_start,
        "window_end": window_start + 20.0,
        "unique_dst_ports": unique_dst_ports,
        "unique_dst_ips": unique_dst_ips,
        "failed_flow_ratio": failed_flow_ratio,
        "max_flows_same_target": max_flows_same_target,
        "dns_query_count": dns_query_count,
        "avg_qname_length": avg_qname_length,
        "nxdomain_ratio": nxdomain_ratio,
        "bytes_out_external": bytes_out_external,
        "out_in_ratio": out_in_ratio,
        "first_frame": first_frame,
        "last_frame": last_frame,
        "if_score": None,
        "if_flag": 0,
        "top_features_json": None,
    }


def test_insufficient_baseline_refuses_training(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_if.db"
    # Only 30 windows (below min_baseline_windows=50)
    baseline_rows = [make_feature_row(window_start=i*20.0) for i in range(30)]

    with pytest.raises(ValueError, match="Baseline has 30 host-window rows, minimum required is 50"):
        train_baseline_model(baseline_rows, model_name="test_short", config=config, db_path=db_path)


def test_train_minimum_baseline_accepted(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_if.db"
    # 55 benign baseline windows
    baseline_rows = [make_feature_row(window_start=i*20.0) for i in range(55)]

    bundle = train_baseline_model(baseline_rows, model_name="test_ok", config=config, db_path=db_path)

    assert "model" in bundle
    assert "scaler" in bundle
    assert "threshold" in bundle
    assert bundle["threshold"] > 0.0


def test_benign_windows_do_not_force_anomalies(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_if.db"
    # Train model on 60 benign windows
    baseline_rows = [make_feature_row(window_start=i*20.0) for i in range(60)]
    bundle = train_baseline_model(baseline_rows, model_name="test_benign", config=config, db_path=db_path)

    # Score normal benign test window
    normal_test_row = [make_feature_row(window_start=2000.0)]
    findings, updated_rows = score_windows_with_model(normal_test_row, bundle, config=config)

    assert len(findings) == 0  # Benign window is below calibrated threshold
    assert updated_rows[0]["if_flag"] == 0
    assert updated_rows[0]["if_score"] is not None


def test_obvious_anomalous_window_detected(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_if.db"
    # Train model on 60 typical benign windows
    baseline_rows = [make_feature_row(window_start=i*20.0) for i in range(60)]
    bundle = train_baseline_model(baseline_rows, model_name="test_anom", config=config, db_path=db_path)

    # Extreme anomalous window: massive outbound byte spike (100 MB outbound vs baseline 1.5 KB)
    extreme_row = [
        make_feature_row(
            window_start=5000.0,
            bytes_out_external=100000000,
            out_in_ratio=500.0,
            unique_dst_ports=100,
        )
    ]

    findings, updated_rows = score_windows_with_model(extreme_row, bundle, config=config)

    assert len(findings) == 1
    f = findings[0]
    assert f.alert_type == "ml_anomaly"
    assert f.detector == "iforest"
    assert f.confidence == 0.5
    assert f.stage in ("Possible Exfiltration", "Reconnaissance", "Unclassified")
    assert "behaved unlike the baseline" in f.summary
    assert updated_rows[0]["if_flag"] == 1


def test_missing_model_file_handled():
    with pytest.raises(FileNotFoundError, match="Model file not found"):
        load_model_bundle("non_existent_model_xyz")


def test_iforest_determinism(tmp_path):
    config = load_config()
    db_path = tmp_path / "test_if.db"
    baseline_rows = [make_feature_row(window_start=i*20.0) for i in range(60)]

    bundle1 = train_baseline_model(baseline_rows, model_name="test_det1", config=config, db_path=db_path)
    bundle2 = train_baseline_model(baseline_rows, model_name="test_det2", config=config, db_path=db_path)

    assert bundle1["threshold"] == bundle2["threshold"]
