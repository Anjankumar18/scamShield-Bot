import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    raise Exception("VT_API_KEY not set")


def scan_url_vt(url: str):

    headers = {
        "x-apikey": VT_API_KEY
    }

    # Step 1: Submit URL
    submit_url = "https://www.virustotal.com/api/v3/urls"

    data = {
        "url": url
    }

    res = requests.post(
        submit_url,
        headers=headers,
        data=data,
        timeout=20
    )

    res.raise_for_status()

    analysis_id = res.json()["data"]["id"]

    # Step 2: Get Analysis
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    report = requests.get(
        report_url,
        headers=headers,
        timeout=20
    )

    report.raise_for_status()

    stats = report.json()["data"]["attributes"]["stats"]

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }
