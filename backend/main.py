from fastapi import FastAPI, UploadFile
import requests
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
app = FastAPI(title="AI Mobile Sec Scanner")

def mobsf_headers():
    return {"Authorization": os.getenv("MOBSF_API_KEY")}

@app.post("/scan")
async def scan_app(file: UploadFile):
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
    headers = mobsf_headers()

    # 1. 上传到MobSF
    file_data = await file.read()
    files = {'file': (file.filename, file_data, 'application/octet-stream')}
    upload_resp = requests.post(f"{mobsf_url}/api/v1/upload", files=files, headers=headers)
    upload_data = upload_resp.json()
    if 'hash' not in upload_data:
        return {"error": "MobSF upload failed", "detail": upload_data}
    scan_id = upload_data['hash']

    # 2. 触发扫描
    requests.post(f"{mobsf_url}/api/v1/scan", data={"hash": scan_id, "scan_type": upload_data.get("scan_type", "apk")}, headers=headers)

    # 3. 获取MobSF报告
    report_resp = requests.post(f"{mobsf_url}/api/v1/report_json", data={"hash": scan_id}, headers=headers)
    report = report_resp.json()

    # 4. Gemini AI 生成安全摘要
    summary_data = {
        "app_name": report.get("app_name", ""),
        "package_name": report.get("package_name", ""),
        "version_name": report.get("version_name", ""),
        "permissions": list(report.get("permissions", {}).keys())[:20],
        "security_score": report.get("security_score", ""),
        "trackers": report.get("trackers", {}).get("detected_trackers", []),
    }
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    ai_prompt = (
        "You are a mobile security researcher. Analyze this Android app security scan summary and provide:\n"
        "1. A professional summary of the app's security posture\n"
        "2. The top security risks based on permissions and trackers\n"
        "3. Recommended security improvements for the developer\n\n"
        f"Scan summary:\n{summary_data}"
    )
    ai_response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=ai_prompt,
    )

    return {"report": report, "ai_summary": ai_response.text}
