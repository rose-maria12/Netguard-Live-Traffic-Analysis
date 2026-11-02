import pytest
from pathlib import Path
from netguard.config import load_config
from netguard.db import init_db
from netguard.pipeline import import_capture, run_analysis
from netguard.reports.json_report import export_run_json

DATA_DIR = Path(__file__).resolve().parent / "data"
PCAPS_DIR = DATA_DIR / "pcaps"


def test_repeatable_analysis_determinism(tmp_path):
    db_path1 = tmp_path / "det1.db"
    db_path2 = tmp_path / "det2.db"
    init_db(db_path1)
    init_db(db_path2)
    config = load_config()

    pcap_file = PCAPS_DIR / "multi_stage.pcap"

    # Run 1
    cap1 = import_capture(pcap_file, db_path=db_path1, config=config)
    res1 = run_analysis(cap1["id"], db_path=db_path1, config=config)
    export1 = export_run_json(res1["run_id"], db_path=db_path1)

    # Run 2
    cap2 = import_capture(pcap_file, db_path=db_path2, config=config)
    res2 = run_analysis(cap2["id"], db_path=db_path2, config=config)
    export2 = export_run_json(res2["run_id"], db_path=db_path2)

    # Normalize variable execution timestamps before comparison
    export1["run"]["started_at"] = 0
    export1["run"]["finished_at"] = 0
    export1["capture"]["imported_at"] = 0
    for inc in export1["incidents"]:
        inc["created_at"] = 0
        inc["updated_at"] = 0

    export2["run"]["started_at"] = 0
    export2["run"]["finished_at"] = 0
    export2["capture"]["imported_at"] = 0
    for inc in export2["incidents"]:
        inc["created_at"] = 0
        inc["updated_at"] = 0

    assert export1["alerts"] == export2["alerts"]
    assert export1["incidents"] == export2["incidents"]
