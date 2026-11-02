import pytest
from pathlib import Path
from netguard.config import load_config
from netguard.db import init_db
from netguard.detection.iforest import train_baseline_model, load_model_bundle
from netguard.pipeline import import_capture, run_analysis
from netguard.web.app import create_app

DATA_DIR = Path(__file__).resolve().parent / "data"
PCAPS_DIR = DATA_DIR / "pcaps"


def test_corrupted_pcap_handling(tmp_path):
    db_path = tmp_path / "corrupt.db"
    init_db(db_path)
    bad_pcap = tmp_path / "corrupt.pcap"
    bad_pcap.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")

    with pytest.raises(ValueError) as exc_info:
        import_capture(bad_pcap, db_path=db_path)
    assert "Invalid magic bytes" in str(exc_info.value)


def test_unsupported_file_format(tmp_path):
    db_path = tmp_path / "unsupported.db"
    init_db(db_path)
    txt_file = tmp_path / "test.txt"
    txt_file.write_text("Hello World")

    with pytest.raises(ValueError) as exc_info:
        import_capture(txt_file, db_path=db_path)
    assert "Invalid magic bytes" in str(exc_info.value)


def test_oversized_pcap_handling(tmp_path):
    db_path = tmp_path / "oversize.db"
    init_db(db_path)
    config = load_config()
    config["general"]["max_pcap_mb"] = 1  # 1 MB threshold

    large_file = tmp_path / "large.pcap"
    # Create fake file larger than 1MB with valid PCAP header
    with open(large_file, "wb") as f:
        f.write(b"\xa1\xb2\xc3\xd4" + b"\x00" * (2 * 1024 * 1024))

    with pytest.raises(ValueError) as exc_info:
        import_capture(large_file, db_path=db_path, config=config)
    assert "exceeds limit" in str(exc_info.value)


def test_benign_pcap_no_suspicious_traffic(tmp_path):
    db_path = tmp_path / "benign.db"
    init_db(db_path)
    config = load_config()

    benign_pcap = PCAPS_DIR / "benign.pcap"
    cap = import_capture(benign_pcap, db_path=db_path, config=config)
    res = run_analysis(cap["id"], db_path=db_path, config=config)

    assert res["status"] == "completed"
    assert res["alerts_count"] == 0
    assert res["incidents_count"] == 0


def test_single_detector_firing(tmp_path):
    db_path = tmp_path / "single_det.db"
    init_db(db_path)
    config = load_config()

    ps_pcap = PCAPS_DIR / "port_scan.pcap"
    cap = import_capture(ps_pcap, db_path=db_path, config=config)
    res = run_analysis(cap["id"], db_path=db_path, config=config)

    assert res["status"] == "completed"
    assert res["alerts_count"] == 1
    assert res["incidents_count"] == 1
    assert res["incidents"][0].alerts[0].alert_type == "port_scan"


def test_insufficient_iforest_baseline_refused(tmp_path):
    # Less than 50 rows should be refused for baseline training
    baseline_rows = [{"unique_dst_ports": 1}] * 10
    with pytest.raises(ValueError) as exc_info:
        train_baseline_model(baseline_rows, model_name="insufficient_test")
    assert "minimum required is 50" in str(exc_info.value)


def test_missing_model_file_handled_gracefully():
    with pytest.raises(FileNotFoundError) as exc_info:
        load_model_bundle("non_existent_model_name_xyz")
    assert "Model file not found" in str(exc_info.value)


def test_disabled_detector(tmp_path):
    db_path = tmp_path / "disabled.db"
    init_db(db_path)
    config = load_config()
    config["detectors"]["port_scan"]["enabled"] = False

    ps_pcap = PCAPS_DIR / "port_scan.pcap"
    cap = import_capture(ps_pcap, db_path=db_path, config=config)
    res = run_analysis(cap["id"], db_path=db_path, config=config)

    assert res["status"] == "completed"
    # Port scan detector disabled, so no port_scan alert generated
    ps_alerts = [a for inc in res["incidents"] for a in inc.alerts if a.alert_type == "port_scan"]
    assert len(ps_alerts) == 0


def test_allowlisted_traffic(tmp_path):
    db_path = tmp_path / "allowlist.db"
    init_db(db_path)
    config = load_config()
    config["allowlist"]["src_ips"] = ["192.168.1.100"]  # Allowlist port scan attacker

    ps_pcap = PCAPS_DIR / "port_scan.pcap"
    cap = import_capture(ps_pcap, db_path=db_path, config=config)
    res = run_analysis(cap["id"], db_path=db_path, config=config)

    assert res["status"] == "completed"
    assert res["alerts_count"] == 0


def test_repeated_analysis_same_capture(tmp_path):
    db_path = tmp_path / "repeat.db"
    init_db(db_path)
    config = load_config()

    ps_pcap = PCAPS_DIR / "port_scan.pcap"
    cap1 = import_capture(ps_pcap, db_path=db_path, config=config)
    res1 = run_analysis(cap1["id"], db_path=db_path, config=config)

    # Re-importing same SHA-256 returns existing capture record
    cap2 = import_capture(ps_pcap, db_path=db_path, config=config)
    assert cap1["id"] == cap2["id"]

    res2 = run_analysis(cap2["id"], db_path=db_path, config=config)
    assert res1["alerts_count"] == res2["alerts_count"]
