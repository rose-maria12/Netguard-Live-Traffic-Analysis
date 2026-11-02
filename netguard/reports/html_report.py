import html
import json
import time
from pathlib import Path
from typing import Any, Dict, Union

from netguard.db import DEFAULT_DB_PATH
from netguard.evidence.timeline import build_incident_timeline
from netguard.reports.json_report import export_run_json


def generate_html_report(run_id: int, db_path: Union[str, Path] = DEFAULT_DB_PATH) -> str:
    """
    Generate a complete, self-contained, offline HTML report for an analyzed capture/run.
    Contains no external CDN or JavaScript dependencies.
    """
    data = export_run_json(run_id, db_path=db_path)

    run = data.get("run", {})
    cap = data.get("capture", {})
    ml_model = data.get("ml_model") or {}
    feature_windows = data.get("feature_windows") or []
    limitations = data.get("limitations") or []
    alerts = data.get("alerts", [])
    incidents = data.get("incidents", [])

    # Calculate high-level stats
    total_alerts = len(alerts)
    rule_alerts = sum(1 for a in alerts if a.get("detector") == "rule")
    ml_alerts = sum(1 for a in alerts if a.get("detector") == "iforest")
    high_crit_incidents = sum(1 for i in incidents if i.get("level") in ("high", "critical"))

    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(run.get("started_at", time.time())))

    # Build HTML content using Python string formatting
    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetGuard Forensic Analysis Report - Run #{run_id}</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #334155;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --accent-crit: #ef4444;
            --accent-high: #f97316;
            --accent-med: #eab308;
            --accent-low: #3b82f6;
            --accent-ok: #22c55e;
        }}
        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .title-group h1 {{
            margin: 0;
            font-size: 26px;
            color: var(--primary);
            letter-spacing: -0.5px;
        }}
        .title-group p {{
            margin: 4px 0 0 0;
            color: var(--text-muted);
            font-size: 14px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-block;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-crit); border: 1px solid var(--accent-crit); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--accent-high); border: 1px solid var(--accent-high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--accent-med); border: 1px solid var(--accent-med); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-low); border: 1px solid var(--accent-low); }}
        .badge-info {{ background: rgba(56, 189, 248, 0.2); color: var(--primary); border: 1px solid var(--primary); }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .card .metric-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }}
        .card .metric-value {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
            color: var(--text-main);
        }}
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 28px;
        }}
        .section h2 {{
            margin-top: 0;
            font-size: 18px;
            color: var(--primary);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 12px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
        }}
        tr:hover {{
            background-color: var(--bg-hover);
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: rgba(15, 23, 42, 0.8);
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
            font-size: 12px;
        }}
        .filter-code {{
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
            background: #090d16;
            border: 1px solid #334155;
            padding: 8px 12px;
            border-radius: 4px;
            color: #a5f3fc;
            margin-top: 4px;
        }}
        .disclaimer-box {{
            background: rgba(234, 179, 8, 0.1);
            border: 1px solid var(--accent-med);
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 13px;
            color: #fef08a;
            margin-bottom: 20px;
        }}
        .timeline-container {{
            margin: 16px 0;
            padding-left: 16px;
            border-left: 2px dashed var(--primary);
        }}
        .timeline-step {{
            margin-bottom: 14px;
            position: relative;
        }}
        .timeline-step::before {{
            content: '';
            position: absolute;
            left: -22px;
            top: 4px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--primary);
        }}
        .timeline-title {{
            font-weight: 600;
            color: var(--primary);
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="title-group">
                <h1>NetGuard Forensic Incident Report</h1>
                <p>Generated for Capture File: <strong>{html.escape(cap.get("filename", "unknown"))}</strong></p>
            </div>
            <div>
                <span class="badge badge-info">Run #{run_id}</span>
                <span style="font-size: 13px; color: var(--text-muted); margin-left: 8px;">{formatted_time}</span>
            </div>
        </div>

        <!-- Metric Cards -->
        <div class="grid">
            <div class="card">
                <div class="metric-label">Processed Packets</div>
                <div class="metric-value">{cap.get("packets_stored", 0):,}</div>
            </div>
            <div class="card">
                <div class="metric-label">Deduplicated Alerts</div>
                <div class="metric-value">{total_alerts}</div>
            </div>
            <div class="card">
                <div class="metric-label">Correlated Incidents</div>
                <div class="metric-value">{len(incidents)}</div>
            </div>
            <div class="card">
                <div class="metric-label">High / Critical Incidents</div>
                <div class="metric-value" style="color: var(--accent-crit);">{high_crit_incidents}</div>
            </div>
        </div>

        <!-- Disclaimer -->
        <div class="disclaimer-box">
            <strong>Prioritization Metric Disclaimer:</strong> Incident scores (0–100 scale) represent a heuristic prioritization metric derived from severity, attack stage diversity, logical progression, and ML corroboration. They are <em>not</em> statistical probabilities and do <em>not</em> constitute automated proof of an attack. Human analyst review is required.
        </div>

        <!-- Capture & Run Metadata -->
        <div class="section">
            <h2>Capture Metadata</h2>
            <table>
                <tr>
                    <th>Filename</th>
                    <td>{html.escape(cap.get("filename", ""))}</td>
                    <th>SHA-256</th>
                    <td><code>{cap.get("sha256", "")}</code></td>
                </tr>
                <tr>
                    <th>Format</th>
                    <td>{cap.get("file_format", "pcap")} ({cap.get("link_type", "Ethernet")})</td>
                    <th>File Size</th>
                    <td>{cap.get("size_bytes", 0) / 1024.0:.1f} KB</td>
                </tr>
                <tr>
                    <th>Total Frames</th>
                    <td>{cap.get("frames_total", 0):,} (Stored: {cap.get("packets_stored", 0):,})</td>
                    <th>Skipped Frames</th>
                    <td>{cap.get("frames_skipped", 0)}</td>
                </tr>
                <tr>
                    <th>Reconstructed Flows</th>
                    <td>{cap.get("flows_count", 0):,}</td>
                    <th>DNS Events</th>
                    <td>{cap.get("dns_events_count", 0):,}</td>
                </tr>
                <tr>
                    <th>Capture ID / Run ID</th>
                    <td>Capture #{cap.get("id", "N/A")} / Run #{run.get("id", run_id)}</td>
                    <th>ML Baseline Model</th>
                    <td>{html.escape(str(ml_model.get("name", "default_baseline")))} (v{html.escape(str(ml_model.get("version", "1.1.0")))}, threshold={float(ml_model.get("threshold") or 0.5978):.4f})</td>
                </tr>
                <tr>
                    <th>NetGuard Version</th>
                    <td>{run.get("netguard_version", "1.0")}</td>
                    <th>Scapy / Sklearn</th>
                    <td>Scapy {run.get("scapy_version", "")} | Sklearn {run.get("sklearn_version", "")}</td>
                </tr>
            </table>
        </div>

        <!-- Correlated Incidents Section -->
        <div class="section">
            <h2>Correlated Incidents ({len(incidents)})</h2>
"""

    if not incidents:
        html_out += "<p style='color: var(--text-muted);'>No correlated incidents found for this capture.</p>"
    else:
        for inc in incidents:
            level = inc.get("level", "low")
            badge_cls = f"badge-{level}"
            breakdown = inc.get("score_breakdown", {})
            involved = ", ".join(inc.get("involved_ips", []))
            stages = " &rarr; ".join(inc.get("stages", []))

            html_out += f"""
            <div style="background: rgba(15, 23, 42, 0.4); border: 1px solid var(--border-color); border-radius: 6px; padding: 16px; margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; font-size: 16px;">
                        Incident #{inc.get("id")} &mdash; Primary IP: <code>{inc.get("primary_ip")}</code>
                    </h3>
                    <div>
                        <span class="badge {badge_cls}">Score: {inc.get("score", 0):.1f} ({level.upper()})</span>
                    </div>
                </div>
                <p style="font-size: 13px; color: var(--text-muted); margin: 8px 0;">{html.escape(inc.get("summary", ""))}</p>
                <div style="font-size: 12px; margin-bottom: 12px;">
                    <strong>Involved IPs:</strong> {involved}<br>
                    <strong>Attack Stages:</strong> {stages}
                </div>

                <!-- Score Breakdown -->
                <div style="font-size: 12px; color: var(--text-muted); background: var(--bg-card); padding: 10px; border-radius: 4px; margin-bottom: 12px;">
                    <strong>Score Breakdown:</strong>
                    Strongest Alert: {breakdown.get("strongest_alert_score", 0)} / {breakdown.get("weights", {}).get("strongest_alert", 35)} |
                    Stage Diversity: {breakdown.get("stage_diversity_score", 0)} / {breakdown.get("weights", {}).get("stage_diversity", 30)} |
                    Logical Order: {breakdown.get("logical_order_score", 0)} / {breakdown.get("weights", {}).get("stage_order", 15)} |
                    Corroboration: {breakdown.get("corroboration_score", 0)} / {breakdown.get("weights", {}).get("corroboration", 20)}
                </div>
            </div>
            """

    html_out += """
        </div>

        <!-- Deduplicated Alerts Section -->
        <div class="section">
            <h2>Deduplicated Alerts & Wireshark Display Filters</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type / Detector</th>
                        <th>Stage</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Merged</th>
                        <th>Wireshark Display Filter</th>
                    </tr>
                </thead>
                <tbody>
"""

    if not alerts:
        html_out += "<tr><td colspan='8' style='text-align: center; color: var(--text-muted);'>No alerts detected.</td></tr>"
    else:
        for a in alerts:
            sev = a.get("severity", "low").lower()
            dst_str = a.get("dst_ip") or "-"
            if a.get("dst_port"):
                dst_str += f":{a.get('dst_port')}"

            filter_str = html.escape(a.get("wireshark_filter", ""))
            bi_filter_str = html.escape(a.get("wireshark_bi_filter", ""))
            precautions_str = html.escape(a.get("suggested_precautions") or "")
            trig_frames = a.get("trigger_frames") or []
            trig_str = f"Exact trigger frames: {trig_frames[:8]}{'...' if len(trig_frames) > 8 else ''} ({len(trig_frames)} total)" if trig_frames else f"Window/flow span: #{a.get('first_frame')}-#{a.get('last_frame')}"
            precautions_html = f'<div style="font-size: 11px; color: var(--primary); margin-top: 6px; padding: 4px 8px; background: rgba(56, 189, 248, 0.1); border-left: 2px solid var(--primary); border-radius: 3px;"><strong>Suggested Precautions / Next Steps:</strong> {precautions_str}</div>' if precautions_str else ''
            html_out += f"""
                <tr>
                    <td>#{a.get("id")}</td>
                    <td><strong>{html.escape(a.get("alert_type", ""))}</strong><br><span style="font-size: 11px; color: var(--text-muted);">{a.get("detector")}</span></td>
                    <td>{html.escape(a.get("stage", ""))}</td>
                    <td><span class="badge badge-{sev}">{sev}</span></td>
                    <td><code>{html.escape(a.get("src_ip", ""))}</code></td>
                    <td><code>{html.escape(dst_str)}</code></td>
                    <td>{a.get("merged_count", 1)}</td>
                    <td>
                        <div style="font-size: 11px; color: var(--text-muted);">Trigger-Direction Filter:</div>
                        <code class="filter-code">{filter_str}</code>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">Bidirectional Investigation Filter:</div>
                        <code class="filter-code">{bi_filter_str}</code>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Window Span: #{a.get("first_frame")}&ndash;#{a.get("last_frame")} &bull; {html.escape(trig_str)}</div>
                        {precautions_html}
                    </td>
                </tr>
            """

    html_out += """
                </tbody>
            </table>
        </div>
"""

    thresh_val = float(ml_model.get("threshold") or 0.5978)
    html_out += f"""
        <div class="section">
            <h2>Isolation Forest Host-Window Scores ({len(feature_windows)} Windows)</h2>
            <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 0;">
                Model: <code>{html.escape(str(ml_model.get("name", "default_baseline")))}.joblib</code> (v{html.escape(str(ml_model.get("version", "1.1.0")))}) &bull;
                Split: {ml_model.get("n_train_rows", 101)} Train / {ml_model.get("n_calib_rows", 49)} Calib (threshold only) / 65 Same-Session Held-Out &bull;
                Decision Rule: <code>if_score &gt; {thresh_val:.4f}</code>
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Window ID</th>
                        <th>Host IP</th>
                        <th>Frame Span</th>
                        <th>Ports</th>
                        <th>Dst IPs</th>
                        <th>Fail Ratio</th>
                        <th>Max Target Flows</th>
                        <th>DNS Q</th>
                        <th>Ext Bytes Out</th>
                        <th>IF Score</th>
                        <th>Decision</th>
                    </tr>
                </thead>
                <tbody>
"""
    if not feature_windows:
        html_out += "<tr><td colspan='11' style='text-align: center; color: var(--text-muted);'>No host feature windows extracted.</td></tr>"
    else:
        for fw in feature_windows:
            sc = fw.get("if_score")
            sc_str = f"{float(sc):.4f}" if sc is not None else "N/A"
            dec_badge = "<span class='badge badge-high'>ANOMALY</span>" if fw.get("if_flag") else "<span class='badge badge-info'>BELOW THRESHOLD</span>"
            html_out += f"""
                    <tr>
                        <td>#{fw.get("id")}</td>
                        <td><code>{html.escape(str(fw.get("host_ip", "")))}</code></td>
                        <td>#{fw.get("first_frame")}&ndash;#{fw.get("last_frame")}</td>
                        <td>{fw.get("unique_dst_ports", 0)}</td>
                        <td>{fw.get("unique_dst_ips", 0)}</td>
                        <td>{float(fw.get("failed_flow_ratio") or 0):.2f}</td>
                        <td>{fw.get("max_flows_same_target", 0)}</td>
                        <td>{fw.get("dns_query_count", 0)}</td>
                        <td>{fw.get("bytes_out_external", 0):,}</td>
                        <td><strong>{sc_str}</strong> (thr {thresh_val:.4f})</td>
                        <td>{dec_badge}</td>
                    </tr>
"""
    html_out += """
                </tbody>
            </table>
            <div style="margin-top: 14px; font-size: 12px; color: var(--text-muted);">
                <strong>Methodological Limitations:</strong>
                <ul style="margin: 6px 0 0 0; padding-left: 20px;">
"""
    for lim in limitations:
        html_out += f"                    <li>{html.escape(lim)}</li>\n"
    html_out += """
                </ul>
            </div>
        </div>

        <!-- Footer -->
        <div style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 32px; border-top: 1px solid var(--border-color); padding-top: 16px;">
            NetGuard Automated Network Intrusion & Forensic Analysis Report &bull; 100% Offline Generation
        </div>
    </div>
</body>
</html>
"""
    return html_out
