from fastapi import FastAPI, UploadFile, BackgroundTasks
from fastapi.responses import HTMLResponse, Response
import httpx
import asyncio
import os
import uuid
import re
import html as html_lib
from datetime import datetime
from dotenv import load_dotenv
from google import genai
from weasyprint import HTML as WeasyHTML

load_dotenv()
app = FastAPI(title="AI Mobile Sec Scanner")

_tasks: dict = {}

# ── Report HTML labels (zh / en) ──────────────────────────────
_LABELS = {
    "zh": {
        "report_title": "📱 移动应用安全分析报告",
        "generated":    "生成于",
        "app_info":     "应用基本信息",
        "app_name":     "应用名称",
        "package":      "包名",
        "version":      "版本号",
        "size":         "文件大小",
        "risk":         "风险概览",
        "critical":     "严重",
        "high":         "高危",
        "warning":      "中危",
        "trackers":     "追踪器",
        "perms":        "危险权限",
        "perm_name":    "权限名称",
        "perm_desc":    "说明",
        "no_perms":     "无危险权限",
        "issues":       "清单文件安全问题",
        "sev":          "级别",
        "issue":        "问题",
        "detail":       "描述",
        "no_issues":    "无问题",
        "ai_title":     "AI 安全分析摘要",
        "footer":       "AI Mobile Security Scanner · MobSF v4.4.5 + Gemini 2.5 Flash · 仅供安全研究参考",
        "sev_map":      {"critical": "严重", "high": "高危", "warning": "中危", "info": "信息"},
        "html_lang":    "zh-CN",
    },
    "en": {
        "report_title": "📱 Mobile App Security Analysis Report",
        "generated":    "Generated at",
        "app_info":     "App Information",
        "app_name":     "App Name",
        "package":      "Package Name",
        "version":      "Version",
        "size":         "File Size",
        "risk":         "Risk Overview",
        "critical":     "Critical",
        "high":         "High",
        "warning":      "Medium",
        "trackers":     "Trackers",
        "perms":        "Dangerous Permissions",
        "perm_name":    "Permission",
        "perm_desc":    "Description",
        "no_perms":     "No dangerous permissions found",
        "issues":       "Manifest Security Issues",
        "sev":          "Severity",
        "issue":        "Issue",
        "detail":       "Details",
        "no_issues":    "No issues found",
        "ai_title":     "AI Security Analysis",
        "footer":       "AI Mobile Security Scanner · MobSF v4.4.5 + Gemini 2.5 Flash · For security research only",
        "sev_map":      {"critical": "CRITICAL", "high": "HIGH", "warning": "MEDIUM", "info": "INFO"},
        "html_lang":    "en",
    },
}


def _mobsf_headers():
    return {"Authorization": os.getenv("MOBSF_API_KEY")}


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path, encoding="utf-8") as f:
        return f.read()


@app.post("/scan")
async def scan_app(file: UploadFile, background_tasks: BackgroundTasks, lang: str = "zh"):
    """Submit APK for scanning. Returns task_id immediately."""
    task_id = str(uuid.uuid4())
    file_data = await file.read()
    _tasks[task_id] = {
        "status": "uploading",
        "filename": file.filename,
        "lang": lang,
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_scan, task_id, file.filename, file_data, lang)
    return {"task_id": task_id}


async def _run_scan(task_id: str, filename: str, file_data: bytes, lang: str = "zh"):
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
    headers = _mobsf_headers()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30, read=300, write=120, pool=30)
        ) as client:
            # 1. Upload to MobSF
            _tasks[task_id]["status"] = "uploading"
            resp = await client.post(
                f"{mobsf_url}/api/v1/upload",
                files={"file": (filename, file_data, "application/octet-stream")},
                headers=headers,
            )
            upload_data = resp.json()
            if "hash" not in upload_data:
                _tasks[task_id].update({"status": "error", "error": str(upload_data)})
                return
            scan_id = upload_data["hash"]

            # 2. Trigger scan
            _tasks[task_id]["status"] = "scanning"
            resp = await client.post(
                f"{mobsf_url}/api/v1/scan",
                data={"hash": scan_id, "scan_type": upload_data.get("scan_type", "apk")},
                headers=headers,
            )
            scan_result = resp.json()
            if "error" in scan_result:
                _tasks[task_id].update({"status": "error", "error": str(scan_result["error"])})
                return

            # 3. Poll for report (max 300s)
            _tasks[task_id]["status"] = "analyzing"
            report = None
            for _ in range(60):
                await asyncio.sleep(5)
                resp = await client.post(
                    f"{mobsf_url}/api/v1/report_json",
                    data={"hash": scan_id},
                    headers=headers,
                )
                data = resp.json()
                if "report" not in data:
                    report = data
                    break

        if report is None:
            _tasks[task_id].update({"status": "error", "error": "Scan timed out (300s)"})
            return

        # 4. Gemini AI summary (bilingual prompt)
        _tasks[task_id]["status"] = "summarizing"
        ai_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        summary_input = {
            "app_name": report.get("app_name", ""),
            "package_name": report.get("package_name", ""),
            "version_name": report.get("version_name", ""),
            "permissions": list(report.get("permissions", {}).keys())[:20],
            "security_score": report.get("security_score") or "N/A",
            "trackers": report.get("trackers", {}).get("detected_trackers", []),
        }
        if lang == "zh":
            prompt = (
                "你是一名专业的移动安全研究员，请用中文分析以下 Android 应用安全扫描摘要，提供：\n"
                "1. 应用安全状况的专业摘要\n"
                "2. 基于权限和追踪器的主要安全风险\n"
                "3. 针对开发者的安全改进建议\n\n"
                f"扫描摘要：\n{summary_input}"
            )
        else:
            prompt = (
                "You are a mobile security researcher. Analyze this Android app security scan "
                "summary and provide:\n"
                "1. A professional summary of the app's security posture\n"
                "2. The top security risks based on permissions and trackers\n"
                "3. Recommended security improvements for the developer\n\n"
                f"Scan summary:\n{summary_input}"
            )
        ai_resp = ai_client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
        _tasks[task_id].update({
            "status": "done",
            "report": report,
            "ai_summary": ai_resp.text,
            "finished_at": datetime.now().isoformat(),
        })

    except Exception as e:
        _tasks[task_id].update({"status": "error", "error": str(e)})


@app.get("/scan/status/{task_id}")
async def get_status(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    return {
        "status": task.get("status", "unknown"),
        "error":  task.get("error"),
    }


def _extract_summary(task: dict) -> dict:
    report = task["report"]
    perms = report.get("permissions", {})

    risk = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    manifest = report.get("manifest_analysis", [])
    if isinstance(manifest, list):
        for item in manifest:
            if not isinstance(item, dict):
                continue
            sev = (item.get("severity") or item.get("level") or "").lower()
            if "critical" in sev:
                risk["critical"] += 1
            elif sev in ("high", "danger"):
                risk["high"] += 1
            elif "warn" in sev or "medium" in sev:
                risk["warning"] += 1
            else:
                risk["info"] += 1

    code = report.get("code_analysis", {})
    if isinstance(code, dict):
        for _, fdata in (code.get("findings") or {}).items():
            if not isinstance(fdata, dict):
                continue
            sev = (fdata.get("metadata", {}).get("severity") or "").lower()
            if "critical" in sev:
                risk["critical"] += 1
            elif sev in ("high",):
                risk["high"] += 1
            elif "warn" in sev or "medium" in sev:
                risk["warning"] += 1
            else:
                risk["info"] += 1

    dangerous_perms = [
        {"name": k, "info": v.get("info", ""), "description": v.get("description", "")}
        for k, v in perms.items()
        if isinstance(v, dict) and v.get("status") == "dangerous"
    ]

    manifest_issues = []
    if isinstance(manifest, list):
        for item in manifest:
            if isinstance(item, dict):
                manifest_issues.append({
                    "title":       item.get("title") or item.get("rule", ""),
                    "severity":    item.get("severity") or item.get("level", ""),
                    "description": item.get("description", ""),
                })

    trackers_data = report.get("trackers", {})
    tracker_count = trackers_data.get("detected_trackers", 0)
    if isinstance(tracker_count, list):
        tracker_count = len(tracker_count)

    return {
        "app_name":            report.get("app_name", "Unknown"),
        "package_name":        report.get("package_name", ""),
        "version_name":        report.get("version_name", ""),
        "size":                report.get("size", ""),
        "md5":                 report.get("md5", ""),
        "security_score":      report.get("security_score") or "N/A",
        "risk_counts":         risk,
        "dangerous_permissions": dangerous_perms[:15],
        "tracker_count":       tracker_count,
        "manifest_issues":     manifest_issues[:20],
        "ai_summary":          task["ai_summary"],
        "finished_at":         task.get("finished_at", ""),
    }


@app.get("/scan/summary/{task_id}")
async def get_summary(task_id: str):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return {"error": "Report not ready"}
    return _extract_summary(task)


@app.get("/scan/report/{task_id}/download")
async def download_report(task_id: str, lang: str = "zh"):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return Response(content="Report not ready", status_code=404)
    summary = _extract_summary(task)
    filename = task.get("filename", "unknown.apk")
    app_name = summary.get("app_name", task_id[:8])
    safe_name = "".join(c for c in app_name if c.isalnum() or c in "-_") or task_id[:8]

    html_content = _build_report_html(summary, filename, lang)
    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(
        None, lambda: WeasyHTML(string=html_content).write_pdf()
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="security-report-{safe_name}.pdf"'
        },
    )


def _md_to_html(text: str) -> str:
    """Convert basic markdown to HTML for PDF rendering."""
    t = html_lib.escape(text)
    t = re.sub(r"^#{3}\s+(.+)$",  r"<h3>\1</h3>",  t, flags=re.MULTILINE)
    t = re.sub(r"^#{2}\s+(.+)$",  r"<h2>\1</h2>",  t, flags=re.MULTILINE)
    t = re.sub(r"^#{1}\s+(.+)$",  r"<h1>\1</h1>",  t, flags=re.MULTILINE)
    t = re.sub(r"\*\*(.+?)\*\*",  r"<strong>\1</strong>", t)
    t = re.sub(r"\*(.+?)\*",      r"<em>\1</em>",         t)
    t = re.sub(r"`(.+?)`",        r"<code>\1</code>",      t)
    # List items → wrap consecutive <li> in <ul>
    t = re.sub(r"^\s*[\*\-]\s+(.+)$", r"<li>\1</li>", t, flags=re.MULTILINE)
    t = re.sub(r"((?:<li>.*?</li>\n?)+)", r"<ul>\1</ul>", t, flags=re.DOTALL)
    # Paragraphs
    blocks = re.split(r"\n{2,}", t)
    out = []
    for b in blocks:
        b = b.strip()
        if not b:
            continue
        if re.match(r"^<(h[1-3]|ul|ol|li)", b):
            out.append(b)
        else:
            out.append(f"<p>{b.replace(chr(10), '<br>')}</p>")
    return "\n".join(out)


def _build_report_html(s: dict, filename: str, lang: str = "zh") -> str:
    """Generate PDF-optimised HTML (A4, cover page, proper pagination)."""
    L = _LABELS.get(lang, _LABELS["zh"])

    def e(v):
        return html_lib.escape(str(v or ""))

    rc       = s.get("risk_counts", {})
    perms    = s.get("dangerous_permissions", [])
    issues   = s.get("manifest_issues", [])
    now      = datetime.now().strftime("%Y-%m-%d %H:%M")
    ai_html  = _md_to_html(s.get("ai_summary", ""))

    SEV_BG    = {"critical": "#fef2f2", "high": "#fff7ed", "warning": "#fffbeb", "info": "#eff6ff"}
    SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "warning": "#d97706", "info": "#2563eb"}
    sev_map   = L["sev_map"]

    # ── Permission rows ──────────────────────────────────────
    perm_rows = ""
    for i, p in enumerate(perms):
        bg = "#f8fafc" if i % 2 == 0 else "#ffffff"
        perm_rows += (
            f"<tr style='background:{bg}'>"
            f"<td style='font-family:monospace;font-size:8.5pt;color:#1e3a8a;"
            f"word-break:break-all;width:52%'>{e(p['name'])}</td>"
            f"<td style='font-size:9pt;color:#374151'>{e(p['info'])}</td>"
            f"</tr>\n"
        )
    if not perm_rows:
        perm_rows = f'<tr><td colspan="2" class="empty">{L["no_perms"]}</td></tr>'

    # ── Issue rows ───────────────────────────────────────────
    issue_rows = ""
    for i, item in enumerate(issues):
        bg  = "#f8fafc" if i % 2 == 0 else "#ffffff"
        sev = str(item.get("severity", "info")).lower()
        lbl = sev_map.get(sev, sev.upper())
        fg  = SEV_COLOR.get(sev, "#6b7280")
        ibg = SEV_BG.get(sev, "#f1f5f9")
        desc = str(item.get("description", ""))
        issue_rows += (
            f"<tr style='background:{bg}'>"
            f"<td style='width:10%;white-space:nowrap'>"
            f"<span style='background:{ibg};color:{fg};font-weight:700;"
            f"font-size:8pt;padding:2px 7px;border-radius:3px'>{lbl}</span></td>"
            f"<td style='width:35%;font-size:9pt;font-weight:600'>{e(item.get('title',''))}</td>"
            f"<td style='font-size:8.5pt;color:#4b5563'>"
            f"{e(desc[:220])}{'…' if len(desc)>220 else ''}</td>"
            f"</tr>\n"
        )
    if not issue_rows:
        issue_rows = f'<tr><td colspan="3" class="empty">{L["no_issues"]}</td></tr>'

    # ── App info rows (2-column table) ───────────────────────
    def meta_row(label, value, mono=False):
        val = f"<span style='font-family:monospace;font-size:8.5pt'>{e(value)}</span>" if mono else e(value)
        return (
            f"<tr>"
            f"<td style='width:30%;color:#6b7280;font-size:8.5pt;font-weight:700;"
            f"text-transform:uppercase;letter-spacing:.04em;padding:9pt 12pt;"
            f"background:#f8fafc;border-bottom:1px solid #e2e8f0'>{label}</td>"
            f"<td style='font-size:10pt;font-weight:600;padding:9pt 12pt;"
            f"border-bottom:1px solid #e2e8f0;word-break:break-all'>{val}</td>"
            f"</tr>"
        )

    meta_rows = (
        meta_row(L["app_name"], s.get("app_name", ""))
        + meta_row(L["package"],  s.get("package_name", ""))
        + meta_row(L["version"],  s.get("version_name", ""))
        + meta_row(L["size"],     s.get("size", ""))
        + meta_row("MD5",         s.get("md5", ""), mono=True)
        + meta_row(L["generated"], now)
    )

    # ── Risk boxes (HTML table, 4 cols) ─────────────────────
    def risk_box(num, label, bg, fg):
        return (
            f"<td style='width:25%;padding:6pt'>"
            f"<div style='background:{bg};border-radius:8pt;padding:18pt 10pt;text-align:center'>"
            f"<div style='font-size:32pt;font-weight:900;color:{fg};line-height:1'>{num}</div>"
            f"<div style='font-size:9pt;font-weight:700;color:{fg};margin-top:5pt'>{label}</div>"
            f"</div></td>"
        )

    risk_boxes = (
        risk_box(rc.get("critical", 0), L["critical"], "#fef2f2", "#dc2626")
        + risk_box(rc.get("high", 0),   L["high"],     "#fff7ed", "#ea580c")
        + risk_box(rc.get("warning", 0),L["warning"],  "#fffbeb", "#d97706")
        + risk_box(s.get("tracker_count", 0), L["trackers"], "#eff6ff", "#2563eb")
    )

    return f"""<!DOCTYPE html>
<html lang="{L['html_lang']}">
<head>
<meta charset="UTF-8">
<title>{e(s.get('app_name',''))} — Security Report</title>
<style>
/* ── Page setup ──────────────────────────── */
@page {{
  size: A4;
  margin: 2cm 2.2cm 2.5cm;
  @bottom-left {{
    content: "{e(s.get('app_name',''))} · {e(filename)}";
    font-size: 7.5pt;
    color: #94a3b8;
    border-top: 1px solid #e2e8f0;
    padding-top: 5pt;
  }}
  @bottom-right {{
    content: counter(page) " / " counter(pages);
    font-size: 7.5pt;
    color: #94a3b8;
    border-top: 1px solid #e2e8f0;
    padding-top: 5pt;
  }}
}}
@page :first {{
  margin: 0;
  @bottom-left  {{ content: none; border: none; }}
  @bottom-right {{ content: none; border: none; }}
}}

/* ── Base ────────────────────────────────── */
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: 'Helvetica Neue', Arial, 'PingFang SC', 'Microsoft YaHei',
               'Noto Sans CJK SC', sans-serif;
  font-size: 10pt;
  color: #1e293b;
  line-height: 1.6;
  background: white;
}}

/* ── Cover page ──────────────────────────── */
.cover {{
  page-break-after: always;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}}
.cover-top {{
  background: #1e3a8a;
  color: white;
  padding: 3cm 2.5cm 2cm;
  flex-shrink: 0;
}}
.cover-top .label {{
  font-size: 9pt;
  letter-spacing: .12em;
  text-transform: uppercase;
  opacity: .7;
  margin-bottom: 12pt;
}}
.cover-top h1 {{
  font-size: 26pt;
  font-weight: 900;
  line-height: 1.2;
  margin-bottom: 8pt;
}}
.cover-top .subtitle {{
  font-size: 11pt;
  opacity: .75;
  margin-bottom: 2cm;
}}
.cover-meta {{
  padding: 0 2.5cm;
  margin-top: 1cm;
}}
.cover-risk {{
  padding: 0 2.5cm;
  margin-top: 1cm;
}}
.cover-bottom {{
  margin-top: auto;
  padding: 1.5cm 2.5cm;
  border-top: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 8.5pt;
  color: #94a3b8;
}}

/* ── Section headings ────────────────────── */
.section {{
  page-break-inside: avoid;
  margin-bottom: 1.2cm;
}}
.section-title {{
  font-size: 11pt;
  font-weight: 800;
  color: #1e3a8a;
  border-bottom: 2.5pt solid #1e3a8a;
  padding-bottom: 5pt;
  margin-bottom: 12pt;
  text-transform: uppercase;
  letter-spacing: .04em;
}}
.section-break {{
  page-break-before: always;
}}

/* ── Tables ──────────────────────────────── */
table.data {{
  width: 100%;
  border-collapse: collapse;
  font-size: 9.5pt;
  page-break-inside: auto;
}}
table.data thead tr {{
  background: #1e3a8a;
  color: white;
}}
table.data thead th {{
  padding: 8pt 12pt;
  text-align: left;
  font-weight: 700;
  font-size: 8.5pt;
  letter-spacing: .04em;
  text-transform: uppercase;
}}
table.data tbody tr {{
  page-break-inside: avoid;
}}
table.data td {{
  padding: 8pt 12pt;
  vertical-align: top;
  border-bottom: 1px solid #e2e8f0;
}}
td.empty {{
  text-align: center;
  color: #94a3b8;
  padding: 14pt;
  font-style: italic;
}}

/* ── AI section ──────────────────────────── */
.ai-content {{
  border-left: 3pt solid #1e3a8a;
  padding-left: 14pt;
  line-height: 1.75;
}}
.ai-content h1, .ai-content h2, .ai-content h3 {{
  color: #1e3a8a;
  margin: 14pt 0 6pt;
  font-size: 10.5pt;
}}
.ai-content h1 {{ font-size: 12pt; }}
.ai-content p  {{ margin: 6pt 0; font-size: 9.5pt; }}
.ai-content ul, .ai-content ol {{ padding-left: 18pt; margin: 6pt 0; }}
.ai-content li {{ margin: 3pt 0; font-size: 9.5pt; }}
.ai-content strong {{ color: #1e293b; }}
.ai-content code {{
  font-family: monospace;
  font-size: 8.5pt;
  background: #f1f5f9;
  padding: 1pt 4pt;
  border-radius: 2pt;
}}
</style>
</head>
<body>

<!-- ══ COVER PAGE ══════════════════════════════════════════ -->
<div class="cover">
  <div class="cover-top">
    <div class="label">Mobile Application Security Report</div>
    <h1>{L['report_title']}</h1>
    <div class="subtitle">Static Analysis · AI Security Assessment</div>
  </div>

  <div class="cover-meta">
    <table style="width:100%;border-collapse:collapse;margin-top:6pt">
      {meta_rows}
    </table>
  </div>

  <div class="cover-risk">
    <div style="font-size:8.5pt;font-weight:700;color:#6b7280;text-transform:uppercase;
                letter-spacing:.06em;margin:16pt 0 8pt">{L['risk']}</div>
    <table style="width:100%;border-collapse:collapse">
      <tr>{risk_boxes}</tr>
    </table>
  </div>

  <div class="cover-bottom">
    <span>AI Mobile Security Scanner · MobSF v4.4.5 + Gemini 2.5 Flash</span>
    <span>{L['generated']}: {now}</span>
  </div>
</div>

<!-- ══ CONTENT PAGES ═══════════════════════════════════════ -->

<!-- § 1 App Info -->
<div class="section">
  <div class="section-title">1. {L['app_info']}</div>
  <table style="width:100%;border-collapse:collapse">
    {meta_rows}
  </table>
</div>

<!-- § 2 Risk Overview -->
<div class="section">
  <div class="section-title">2. {L['risk']}</div>
  <table style="width:100%;border-collapse:collapse">
    <tr>{risk_boxes}</tr>
  </table>
</div>

<!-- § 3 Dangerous Permissions -->
<div class="section">
  <div class="section-title">3. {L['perms']} ({len(perms)})</div>
  <table class="data">
    <thead>
      <tr>
        <th style="width:52%">{L['perm_name']}</th>
        <th>{L['perm_desc']}</th>
      </tr>
    </thead>
    <tbody>{perm_rows}</tbody>
  </table>
</div>

<!-- § 4 Manifest Issues -->
<div class="section section-break">
  <div class="section-title">4. {L['issues']} ({len(issues)})</div>
  <table class="data">
    <thead>
      <tr>
        <th style="width:10%">{L['sev']}</th>
        <th style="width:35%">{L['issue']}</th>
        <th>{L['detail']}</th>
      </tr>
    </thead>
    <tbody>{issue_rows}</tbody>
  </table>
</div>

<!-- § 5 AI Analysis -->
<div class="section section-break">
  <div class="section-title">5. {L['ai_title']}</div>
  <div class="ai-content">{ai_html}</div>
</div>

</body>
</html>"""
