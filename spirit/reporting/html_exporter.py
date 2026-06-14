import os
from datetime import datetime

class HTMLExporter:
    
    def export(self, report_data, output_path=None):
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"spirit_report_{timestamp}.html"
        
        html = self._generate_html(report_data)
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        return output_path
    
    def _generate_html(self, data):
        score = data["score"]["total"]
        zone = data["score"]["zone"]
        
        if zone == "SAFE":
            zone_color = "#00ff88"
            zone_bg = "#003311"
        elif zone == "WARNING":
            zone_color = "#ffaa00"
            zone_bg = "#332200"
        else:
            zone_color = "#ff4444"
            zone_bg = "#330000"
        
        # findings rows
        findings_html = ""
        for f in data["findings"]:
            sev = f["severity"].upper()
            sev_color = {
                "CRITICAL": "#ff4444",
                "HIGH": "#ff8800",
                "MEDIUM": "#ffaa00",
                "LOW": "#4488ff"
            }.get(sev, "#ffffff")
            
            findings_html += f"""
            <tr>
                <td style="color:{sev_color};font-weight:bold">{sev}</td>
                <td>{f['library']}</td>
                <td style="font-size:12px">{f['file']}</td>
                <td>{f['line']}</td>
                <td>{f['message']}</td>
                <td style="color:#00ff88;font-size:12px">{f.get('fix','')}</td>
            </tr>
            """
        
        # history rows
        history_html = ""
        for h in data["history"]:
            h_color = "#00ff88" if h["zone"] == "SAFE" else "#ffaa00" if h["zone"] == "WARNING" else "#ff4444"
            history_html += f"""
            <tr>
                <td>{h['timestamp'][:19]}</td>
                <td style="color:{h_color};font-weight:bold">{h['score']}</td>
                <td style="color:{h_color}">{h['zone']}</td>
                <td>{h['findings_count']}</td>
            </tr>
            """
        
        trend = data.get("trend", "STABLE")
        trend_color = "#00ff88" if trend == "IMPROVING" else "#ff4444" if trend == "DEGRADING" else "#ffaa00"

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>SpiritCLI Security Report</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ 
            background:#0a0f1a; 
            color:#e0e0e0; 
            font-family:'Courier New', monospace;
            padding:30px;
        }}
        .header {{
            text-align:center;
            padding:30px;
            border-bottom:2px solid #00ccff;
            margin-bottom:30px;
        }}
        .title {{
            font-size:48px;
            font-weight:bold;
            color:#00ccff;
            letter-spacing:8px;
        }}
        .subtitle {{
            color:#888;
            margin-top:8px;
        }}
        .score-section {{
            display:flex;
            gap:20px;
            margin-bottom:30px;
            flex-wrap:wrap;
        }}
        .score-card {{
            flex:1;
            min-width:150px;
            background:#111827;
            border:1px solid #1e3a5f;
            border-radius:8px;
            padding:20px;
            text-align:center;
        }}
        .score-card .label {{
            color:#888;
            font-size:12px;
            margin-bottom:8px;
        }}
        .score-card .value {{
            font-size:28px;
            font-weight:bold;
            color:#00ccff;
        }}
        .fingerprint {{
            background:{zone_bg};
            border:2px solid {zone_color};
            border-radius:8px;
            padding:25px;
            text-align:center;
            margin-bottom:30px;
        }}
        .fingerprint .big-score {{
            font-size:64px;
            font-weight:bold;
            color:{zone_color};
        }}
        .fingerprint .zone {{
            font-size:24px;
            color:{zone_color};
            margin-top:8px;
        }}
        .section {{
            background:#111827;
            border:1px solid #1e3a5f;
            border-radius:8px;
            padding:25px;
            margin-bottom:25px;
        }}
        .section-title {{
            color:#00ccff;
            font-size:18px;
            font-weight:bold;
            margin-bottom:15px;
            border-bottom:1px solid #1e3a5f;
            padding-bottom:10px;
        }}
        table {{
            width:100%;
            border-collapse:collapse;
            font-size:13px;
        }}
        th {{
            background:#1e3a5f;
            color:#00ccff;
            padding:10px;
            text-align:left;
        }}
        td {{
            padding:10px;
            border-bottom:1px solid #1a2535;
            vertical-align:top;
        }}
        tr:hover {{ background:#1a2535; }}
        .trend {{
            display:inline-block;
            padding:5px 15px;
            border-radius:20px;
            color:{trend_color};
            border:1px solid {trend_color};
            font-weight:bold;
        }}
        .footer {{
            text-align:center;
            color:#444;
            margin-top:30px;
            padding-top:20px;
            border-top:1px solid #1e3a5f;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">SPIRITCLI</div>
        <div class="subtitle">Real-Time Dependency Security Intelligence for Banking</div>
        <div class="subtitle">Team DrunkenDevs</div>
        <div class="subtitle" style="margin-top:10px">
            Scan: {data['scan_path']} &nbsp;|&nbsp; {data['timestamp'][:19]}
        </div>
    </div>

    <div class="fingerprint">
        <div class="big-score">{score}/100</div>
        <div class="zone">{zone}</div>
    </div>

    <div class="score-section">
        <div class="score-card">
            <div class="label">Config Safety</div>
            <div class="value">{data['score']['config_score']}</div>
        </div>
        <div class="score-card">
            <div class="label">CVE Exposure</div>
            <div class="value">{data['score']['cve_score']}</div>
        </div>
        <div class="score-card">
            <div class="label">Trust Score</div>
            <div class="value">{data['score']['trust_score']}</div>
        </div>
        <div class="score-card">
            <div class="label">Freshness</div>
            <div class="value">{data['score']['freshness_score']}</div>
        </div>
        <div class="score-card">
            <div class="label">Phantom Risk</div>
            <div class="value">{data['score']['phantom_score']}</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">
            Security Findings ({len(data['findings'])} total)
        </div>
        <table>
            <tr>
                <th>Severity</th>
                <th>Library</th>
                <th>File</th>
                <th>Line</th>
                <th>Issue</th>
                <th>Fix</th>
            </tr>
            {findings_html}
        </table>
    </div>

    <div class="section">
        <div class="section-title">
            Scan History &nbsp;
            <span class="trend">{trend}</span>
        </div>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Score</th>
                <th>Zone</th>
                <th>Findings</th>
            </tr>
            {history_html}
        </table>
    </div>

    <div class="footer">
        Generated by SpiritCLI — Team DrunkenDevs
    </div>
</body>
</html>"""