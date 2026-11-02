# NetGuard Architecture

```mermaid
flowchart TD
    subgraph Ingestion
        PCAP["PCAP / PCAPng File"] -->|pcap_reader| Ingest["netguard/ingest/pcap_reader.py"]
        Ingest -->|flow_builder| Flows["netguard/ingest/flow_builder.py"]
    end
    subgraph Feature
        Flows -->|extract_window_features_for_capture| Features["netguard/features/window_features.py (20s tumbling windows, 9 features)"]
    end
    subgraph Detection
        Features -->|detectors| Detectors["netguard/detection/ (port_scan, brute_force, dns_anomaly, outbound, iforest)"
        ]
    end
    subgraph Correlation
        Detectors -->|dedup| Dedup["netguard/correlation/dedup.py"]
        Dedup -->|engine| Engine["netguard/correlation/engine.py"]
    end
    subgraph Scoring & Evidence
        Engine -->|scorer| Scorer["netguard/scoring/scorer.py"]
        Engine -->|evidence| Evidence["netguard/evidence/ (wireshark.py, timeline.py)"]
    end
    subgraph Action
        Scorer -->|firewall| FW["netguard/firewall/windows_fw.py"]
        Scorer -->|report| Report["netguard/reports (html_report, json_report)"]
    end
    subgraph UI
        Report -->|dashboard| UI["netguard/web/app.py (Flask) and templates"]
        FW --> UI
    end
```

The diagram reflects the end‑to‑end data flow from raw captures through feature extraction, rule‑based and ML detection, incident correlation, scoring, firewall enforcement, and the **Flask** SOC dashboard.

## Web Application Framework & Startup Verification (`netguard/web/app.py`)

- **Framework:** **Flask** (`Flask>=3.0.0`, `Jinja2>=3.1.0` in `requirements.txt` — **not** FastAPI).
- **Import Statement (`netguard/web/app.py`, line 15):**
  ```python
  from flask import Flask, Response, flash, jsonify, redirect, render_template, request, session, url_for
  ```
- **Application Factory & Creation (`netguard/web/app.py`, lines 181–189):**
  ```python
  def create_app(db_path: Union[str, Path] = DEFAULT_DB_PATH, test_config: Optional[Dict[str, Any]] = None) -> Flask:
      app = Flask(
          __name__,
          template_folder=os.path.join(os.path.dirname(__file__), "templates"),
          static_folder=os.path.join(os.path.dirname(__file__), "static"),
      )
  ```
- **Entrypoint (`netguard/web/app.py`, lines 1562–1564):**
  ```python
  if __name__ == "__main__":
      app = create_app()
      app.run(host="127.0.0.1", port=5000, debug=True)
  ```
- **Actual Startup Command:**
  ```powershell
  cd d:\netguard\is_project2\is_project
  python netguard/web/app.py
  ```
  Serves the web dashboard at `http://127.0.0.1:5000`.

