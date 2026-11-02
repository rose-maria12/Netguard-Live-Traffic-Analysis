-- NetGuard Database Schema

CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    file_format TEXT NOT NULL,
    link_type TEXT NOT NULL,
    frames_total INTEGER NOT NULL DEFAULT 0,
    packets_stored INTEGER NOT NULL DEFAULT 0,
    frames_skipped INTEGER NOT NULL DEFAULT 0,
    skipped_json TEXT NOT NULL DEFAULT '{}',
    first_ts REAL,
    last_ts REAL,
    source TEXT NOT NULL DEFAULT 'upload',
    status TEXT NOT NULL DEFAULT 'importing',
    error TEXT,
    imported_at REAL NOT NULL,
    netguard_version TEXT NOT NULL,
    scapy_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_captures_sha256 ON captures(sha256);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    frame_no INTEGER NOT NULL,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT NOT NULL,
    length INTEGER NOT NULL,
    tcp_flags INTEGER,
    ttl INTEGER NOT NULL,
    flow_id INTEGER,
    UNIQUE(capture_id, frame_no)
);

CREATE INDEX IF NOT EXISTS idx_packets_capture_ts ON packets(capture_id, ts);
CREATE INDEX IF NOT EXISTS idx_packets_capture_src ON packets(capture_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_capture_dst ON packets(capture_id, dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_id);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    initiator_ip TEXT NOT NULL,
    responder_ip TEXT NOT NULL,
    initiator_port INTEGER,
    responder_port INTEGER,
    proto TEXT NOT NULL,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    pkts_fwd INTEGER NOT NULL DEFAULT 0,
    pkts_rev INTEGER NOT NULL DEFAULT 0,
    bytes_fwd INTEGER NOT NULL DEFAULT 0,
    bytes_rev INTEGER NOT NULL DEFAULT 0,
    syn_count INTEGER NOT NULL DEFAULT 0,
    rst_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    first_frame INTEGER NOT NULL,
    last_frame INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_capture_start ON flows(capture_id, start_ts);
CREATE INDEX IF NOT EXISTS idx_flows_capture_init ON flows(capture_id, initiator_ip);
CREATE INDEX IF NOT EXISTS idx_flows_capture_resp ON flows(capture_id, responder_ip, responder_port);

CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    frame_no INTEGER NOT NULL,
    ts REAL NOT NULL,
    client_ip TEXT NOT NULL,
    server_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    qname_len INTEGER NOT NULL,
    max_label_len INTEGER NOT NULL,
    qtype INTEGER NOT NULL,
    is_response INTEGER NOT NULL,
    rcode INTEGER,
    txid INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_capture_ts ON dns_events(capture_id, ts);
CREATE INDEX IF NOT EXISTS idx_dns_capture_client ON dns_events(capture_id, client_ip);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    model_path TEXT NOT NULL,
    baseline_sha256s_json TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    feature_list_json TEXT NOT NULL,
    n_train_rows INTEGER NOT NULL,
    threshold REAL NOT NULL,
    threshold_percentile REAL NOT NULL,
    baseline_stats_json TEXT NOT NULL,
    params_json TEXT NOT NULL,
    seed INTEGER NOT NULL,
    sklearn_version TEXT NOT NULL,
    trained_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
    model_id INTEGER REFERENCES models(id) ON DELETE SET NULL,
    config_json TEXT NOT NULL,
    config_sha256 TEXT NOT NULL,
    seed INTEGER NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT,
    stats_json TEXT,
    python_version TEXT NOT NULL,
    sklearn_version TEXT NOT NULL,
    scapy_version TEXT NOT NULL,
    netguard_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_capture ON runs(capture_id);

CREATE TABLE IF NOT EXISTS feature_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host_ip TEXT NOT NULL,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    unique_dst_ports INTEGER NOT NULL,
    unique_dst_ips INTEGER NOT NULL,
    failed_flow_ratio REAL NOT NULL,
    max_flows_same_target INTEGER NOT NULL,
    dns_query_count INTEGER NOT NULL,
    avg_qname_length REAL NOT NULL,
    nxdomain_ratio REAL NOT NULL,
    bytes_out_external INTEGER NOT NULL,
    out_in_ratio REAL NOT NULL,
    first_frame INTEGER NOT NULL,
    last_frame INTEGER NOT NULL,
    if_score REAL,
    if_flag INTEGER NOT NULL DEFAULT 0,
    top_features_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_fw_run_host_window ON feature_windows(run_id, host_ip, window_start);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,
    detector TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    dst_port INTEGER,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    stage TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    wireshark_filter TEXT NOT NULL,
    first_frame INTEGER NOT NULL,
    last_frame INTEGER NOT NULL,
    merged_count INTEGER NOT NULL DEFAULT 1,
    dedup_key TEXT NOT NULL,
    evidence_truncated INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_run_type ON alerts(run_id, alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_run_src ON alerts(run_id, src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_run_start ON alerts(run_id, start_ts);

CREATE TABLE IF NOT EXISTS alert_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    ref_type TEXT NOT NULL,
    ref_id INTEGER NOT NULL,
    frame_no INTEGER,
    note TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_alert ON alert_evidence(alert_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    primary_ip TEXT NOT NULL,
    involved_ips_json TEXT NOT NULL,
    start_ts REAL NOT NULL,
    end_ts REAL NOT NULL,
    stages_json TEXT NOT NULL,
    stage_count INTEGER NOT NULL,
    is_multistage INTEGER NOT NULL,
    rule_alert_count INTEGER NOT NULL,
    ml_alert_count INTEGER NOT NULL,
    score REAL NOT NULL,
    level TEXT NOT NULL,
    score_breakdown_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    analyst_notes TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_run_score ON incidents(run_id, score);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    stage TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_ia_alert ON incident_alerts(alert_id);

CREATE TABLE IF NOT EXISTS firewall_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL,
    reason TEXT,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_at REAL NOT NULL,
    expires_at REAL,
    duration_minutes INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    fw_result TEXT,
    removed_at REAL,
    removed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_fw_blocks_status ON firewall_blocks(status);
CREATE INDEX IF NOT EXISTS idx_fw_blocks_ip ON firewall_blocks(ip_address);

CREATE TABLE IF NOT EXISTS firewall_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    ip_address TEXT,
    rule_name TEXT,
    operator TEXT,
    result TEXT,
    detail TEXT,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fw_audit_ts ON firewall_audit(ts);

CREATE TABLE IF NOT EXISTS prevention_config (
    id INTEGER PRIMARY KEY DEFAULT 1,
    mode TEXT NOT NULL DEFAULT 'monitor',
    auto_block_min_severity TEXT NOT NULL DEFAULT 'high',
    max_concurrent_blocks INTEGER NOT NULL DEFAULT 20,
    default_duration_minutes INTEGER NOT NULL DEFAULT 15,
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 10,
    updated_at REAL,
    updated_by TEXT
);
