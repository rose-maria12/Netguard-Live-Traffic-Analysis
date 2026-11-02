"""
Unit and integration tests for NetGuard Authentic Dataset Benchmarking (CIC-IDS2017 & UNSW-NB15).
"""
from pathlib import Path
import pytest

from netguard.datasets.benchmark import (
    DATASET_REGISTRY,
    evaluate_csv_dataset,
    map_cicflowmeter_row,
)
from netguard.db import init_db
from netguard.web.app import create_app

SAMPLE_CSV = Path(__file__).resolve().parent / "data" / "datasets" / "cic_ids2017_sample.csv"


def test_dataset_registry_metadata():
    assert "CIC-IDS2017" in DATASET_REGISTRY
    assert "UNSW-NB15" in DATASET_REGISTRY

    cic = DATASET_REGISTRY["CIC-IDS2017"]
    assert cic.year == 2017
    assert cic.pcap_available is True
    assert "PortScan" in cic.supported_attacks
    assert "unb.ca" in cic.official_url

    unsw = DATASET_REGISTRY["UNSW-NB15"]
    assert unsw.year == 2015
    assert "Reconnaissance" in unsw.supported_attacks


def test_map_cicflowmeter_row():
    raw_row = {
        " Destination Port": " 22 ",
        " Flow Duration": " 500000 ",
        " Total Fwd Packets": " 4 ",
        " Total Backward Packets": " 3 ",
        " Total Length of Fwd Packets": " 280 ",
        " Total Length of Bwd Packets": " 220 ",
        " SYN Flag Count": " 1 ",
        " RST Flag Count": " 0 ",
        " Label": " SSH-Patator ",
    }
    mapped = map_cicflowmeter_row(raw_row)
    assert mapped["dport"] == 22
    assert mapped["duration"] == 0.5
    assert mapped["packets_fwd"] == 4
    assert mapped["is_malicious"] is True
    assert mapped["state"] == "established"
    assert mapped["initiator_ip"] == "192.168.10.50"


def test_evaluate_csv_dataset():
    assert SAMPLE_CSV.exists()
    results = evaluate_csv_dataset(SAMPLE_CSV, dataset_name="CIC-IDS2017")

    assert "metrics" in results
    assert "confusion_matrix" in results
    assert "attack_breakdown" in results

    m = results["metrics"]
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0

    cm = results["confusion_matrix"]
    assert cm["TN"] == 8
    assert cm["FP"] == 0
    assert cm["TP"] == 35
    assert cm["FN"] == 0

    assert "PortScan" in results["attack_breakdown"]
    assert "SSH-Patator" in results["attack_breakdown"]


def test_web_benchmark_endpoint(tmp_path):
    db_file = tmp_path / "test_bench_web.db"
    init_db(db_file)
    app = create_app(db_path=db_file, test_config={"TESTING": True, "WTF_CSRF_ENABLED": False})

    with app.test_client() as client:
        res = client.post(
            "/api/benchmark/run",
            json={"csv_path": str(SAMPLE_CSV), "dataset_name": "CIC-IDS2017"},
            headers={"X-NetGuard-Auth": "test-bypass"},
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert data["results"]["metrics"]["precision"] == 1.0
