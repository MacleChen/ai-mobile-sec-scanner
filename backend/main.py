from fastapi import FastAPI, UploadFile, BackgroundTasks
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import os
import uuid
import re
import html as html_lib
from datetime import datetime
from dotenv import load_dotenv
from google import genai

load_dotenv()
app = FastAPI(title="AI Mobile Sec Scanner")

# In-memory task store: {task_id: {...}}
_tasks: dict = {}

STATUS_MESSAGES = {
    "uploading":   "正在上传 APK 到分析引擎...",
    "scanning":    "MobSF 静态分析中，请耐心等待...",
    "analyzing":   "等待分析报告生成...",
    "summarizing": "AI 正在生成安全摘要...",
    "done":        "扫描完成 ✅",
    "error":       "扫描出错 ❌",
}


def _mobsf_headers():
    return {"Authorization": os.getenv("MOBSF_API_KEY")}


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path, encoding="utf-8") as f:
        return f.read()


@app.post("/scan")
async def scan_app(file: UploadFile, background_tasks: BackgroundTasks):
    """Submit APK for scanning. Returns task_id immediately."""
    task_id = str(uuid.uuid4())
    file_data = await file.read()
    _tasks[task_id] = {
        "status": "uploading",
        "filename": file.filename,
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_scan, task_id, file.filename, file_data)
    return {"task_id": task_id}


async def _run_scan(task_id: str, filename: str, file_data: bytes):
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
                _tasks[task_id].update({"status": "error", "error": f"上传失败: {upload_data}"})
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
                _tasks[task_id].update({"status": "error", "error": f"扫描失败: {scan_result['error']}"})
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
            _tasks[task_id].update({"status": "error", "error": "扫描超时（300s），请重试"})
            return

        # 4. Gemini AI summary
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
        ai_resp = ai_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=(
                "You are a mobile security researcher. Analyze this Android app security scan "
                "summary and provide:\n"
                "1. A professional summary of the app's security posture\n"
                "2. The top security risks based on permissions and trackers\n"
                "3. Recommended security improvements for the developer\n\n"
                f"Scan summary:\n{summary_input}"
            ),
        )
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
    status = task.get("status", "unknown")
    return {
        "status": status,
        "message": STATUS_MESSAGES.get(status, status),
        "error": task.get("error"),
    }


def _extract_summary(task: dict) -> dict:
    report = task["report"]
    perms = report.get("permissions", {})

    # Count findings by severity
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
                    "title": item.get("title") or item.get("rule", ""),
                    "severity": item.get("severity") or item.get("level", ""),
                    "description": item.get("description", ""),
                })

    trackers_data = report.get("trackers", {})
    tracker_count = trackers_data.get("detected_trackers", 0)
    if isinstance(tracker_count, list):
        tracker_count = len(tracker_count)

    return {
        "app_name": report.get("app_name", "Unknown"),
        "package_name": report.get("package_name", ""),
        "version_name": report.get("version_name", ""),
        "size": report.get("size", ""),
        "md5": report.get("md5", ""),
        "security_score": report.get("security_score") or "N/A",
        "risk_counts": risk,
        "dangerous_permissions": dangerous_perms[:15],
        "tracker_count": tracker_count,
        "manifest_issues": manifest_issues[:20],
        "ai_summary": task["ai_summary"],
        "finished_at": task.get("finished_at", ""),
    }


@app.get("/scan/summary/{task_id}")
async def get_summary(task_id: str):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return {"error": "报告未就绪"}
    return _extract_summary(task)


@app.get("/scan/report/{task_id}/download", response_class=HTMLResponse)
async def download_report(task_id: str):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return HTMLResponse("<h1>报告未就绪</h1>", status_code=404)
    summary = _extract_summary(task)
    html = _build_report_html(summary, task.get("filename", "unknown.apk"))
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="security-report-{task_id[:8]}.html"'
        },
    )


def _build_report_html(s: dict, filename: str) -> str:
    """Generate a standalone downloadable HTML security report."""

    def e(v):
        return html_lib.escape(str(v or ""))

    # Render AI markdown (basic subset)
    ai_md = s.get("ai_summary", "")
    ai_html = e(ai_md)
    ai_html = re.sub(r"###\s+(.+)", r"<h3>\1</h3>", ai_html)
    ai_html = re.sub(r"##\s+(.+)", r"<h2 style='color:#1e40af;margin:18px 0 8px'>\1</h2>", ai_html)
    ai_html = re.sub(r"#\s+(.+)", r"<h1 style='color:#1e40af'>\1</h1>", ai_html)
    ai_html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", ai_html)
    ai_html = re.sub(r"\*(.+?)\*", r"<em>\1</em>", ai_html)
    ai_html = re.sub(r"^\s*[\*\-]\s+(.+)$", r"<li>\1</li>", ai_html, flags=re.MULTILINE)
    ai_html = re.sub(r"(<li>.*?</li>(\n|$))+", lambda m: f"<ul>{m.group(0)}</ul>", ai_html, flags=re.DOTALL)
    ai_html = ai_html.replace("\n\n", "</p><p>").replace("\n", "<br>")
    ai_html = f"<p>{ai_html}</p>"

    SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "warning": "#d97706", "info": "#2563eb"}

    perm_rows = "".join(
        f"<tr><td><code>{e(p['name'])}</code></td><td>{e(p['info'])}</td></tr>"
        for p in s.get("dangerous_permissions", [])
    ) or '<tr><td colspan="2" class="empty">无危险权限</td></tr>'

    issue_rows = ""
    for item in s.get("manifest_issues", []):
        sev = str(item.get("severity", "info")).lower()
        color = SEV_COLOR.get(sev, "#6b7280")
        label = {"critical": "严重", "high": "高危", "warning": "中危", "info": "信息"}.get(sev, sev.upper())
        desc = str(item.get("description", ""))
        issue_rows += (
            f"<tr>"
            f"<td><span style='color:{color};font-weight:700;background:{color}18;padding:2px 8px;border-radius:4px'>{label}</span></td>"
            f"<td>{e(item.get('title', ''))}</td>"
            f"<td class='desc'>{e(desc[:180])}{'...' if len(desc) > 180 else ''}</td>"
            f"</tr>\n"
        )
    if not issue_rows:
        issue_rows = '<tr><td colspan="3" class="empty">无问题</td></tr>'

    rc = s.get("risk_counts", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>安全报告 - {e(s.get('app_name', ''))}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;color:#1e293b;padding:24px}}
  .wrap{{max-width:960px;margin:0 auto}}
  .header{{background:linear-gradient(135deg,#1e40af,#3b82f6);color:white;padding:36px 40px;border-radius:16px 16px 0 0}}
  .header h1{{font-size:1.7em;font-weight:800}}
  .header .sub{{opacity:.8;margin-top:6px;font-size:.9em}}
  .section{{background:white;border-radius:0;padding:32px 40px;border-bottom:1px solid #f1f5f9}}
  .section:last-child{{border-radius:0 0 16px 16px;border-bottom:none}}
  h2{{font-size:1.05em;font-weight:700;color:#374151;padding-bottom:10px;border-bottom:2px solid #e2e8f0;margin-bottom:18px}}
  .info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
  .info-item{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px}}
  .info-item label{{color:#94a3b8;font-size:.72em;font-weight:700;text-transform:uppercase;letter-spacing:.06em}}
  .info-item p{{font-weight:600;margin-top:4px;font-size:.95em;word-break:break-all}}
  .info-item.wide{{grid-column:1/-1}}
  .risk-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
  .risk-box{{border-radius:12px;padding:20px 12px;text-align:center}}
  .risk-box .num{{font-size:2.4em;font-weight:800;line-height:1}}
  .risk-box .lbl{{font-size:.8em;font-weight:700;margin-top:6px}}
  .rc{{background:#fef2f2;color:#dc2626}}.rh{{background:#fff7ed;color:#ea580c}}
  .rw{{background:#fffbeb;color:#d97706}}.rt{{background:#eff6ff;color:#2563eb}}
  table{{width:100%;border-collapse:collapse;font-size:.88em}}
  th{{background:#f8fafc;padding:10px 14px;text-align:left;font-weight:700;color:#6b7280;font-size:.78em;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
  tr:hover td{{background:#f8fafc}}
  td.desc{{color:#64748b;font-size:.85em}}
  td.empty{{color:#94a3b8;text-align:center;padding:20px}}
  code{{font-family:monospace;font-size:.85em;background:#f1f5f9;padding:2px 8px;border-radius:4px;word-break:break-all}}
  .ai-box{{background:#f0f9ff;border-left:4px solid #0ea5e9;padding:24px 28px;border-radius:0 10px 10px 0;line-height:1.8}}
  .ai-box h3{{color:#1e40af;margin:16px 0 8px}}
  .ai-box ul{{padding-left:20px;margin:8px 0}}
  .ai-box li{{margin:4px 0}}
  .ai-box p{{margin:8px 0}}
  .footer{{text-align:center;color:#94a3b8;font-size:.82em;padding:20px;background:white;border-radius:0 0 16px 16px;border-top:1px solid #e2e8f0}}
  @media print{{body{{padding:0;background:white}}.wrap .section{{box-shadow:none}}}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>📱 移动应用安全分析报告</h1>
    <div class="sub">{e(filename)} &nbsp;·&nbsp; 生成于 {now}</div>
  </div>

  <div class="section">
    <h2>应用基本信息</h2>
    <div class="info-grid">
      <div class="info-item"><label>应用名称</label><p>{e(s.get('app_name',''))}</p></div>
      <div class="info-item"><label>包名</label><p>{e(s.get('package_name',''))}</p></div>
      <div class="info-item"><label>版本号</label><p>{e(s.get('version_name',''))}</p></div>
      <div class="info-item"><label>文件大小</label><p>{e(s.get('size',''))}</p></div>
      <div class="info-item wide"><label>MD5</label><p><code>{e(s.get('md5',''))}</code></p></div>
    </div>
  </div>

  <div class="section">
    <h2>风险概览</h2>
    <div class="risk-grid">
      <div class="risk-box rc"><div class="num">{rc.get('critical',0)}</div><div class="lbl">严重</div></div>
      <div class="risk-box rh"><div class="num">{rc.get('high',0)}</div><div class="lbl">高危</div></div>
      <div class="risk-box rw"><div class="num">{rc.get('warning',0)}</div><div class="lbl">中危</div></div>
      <div class="risk-box rt"><div class="num">{s.get('tracker_count',0)}</div><div class="lbl">追踪器</div></div>
    </div>
  </div>

  <div class="section">
    <h2>危险权限（{len(s.get('dangerous_permissions',[]))} 项）</h2>
    <table>
      <tr><th>权限名称</th><th>说明</th></tr>
      {perm_rows}
    </table>
  </div>

  <div class="section">
    <h2>清单文件安全问题（{len(s.get('manifest_issues',[]))} 项）</h2>
    <table>
      <tr><th>级别</th><th>问题</th><th>描述</th></tr>
      {issue_rows}
    </table>
  </div>

  <div class="section">
    <h2>AI 安全分析摘要</h2>
    <div class="ai-box">{ai_html}</div>
  </div>

  <div class="footer">
    AI Mobile Security Scanner &nbsp;·&nbsp; MobSF v4.4.5 + Gemini 2.5 Flash &nbsp;·&nbsp; 仅供安全研究参考
  </div>
</div>
</body>
</html>"""
