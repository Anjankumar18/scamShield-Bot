import os
import requests
import base64


VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3/urls"


def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def scan_url(url: str) -> dict:

    headers = {
        "x-apikey": VT_KEY
    }

    # Submit URL
    requests.post(
        VT_URL,
        headers=headers,
        data={"url": url}
    )

    # Get report
    url_id = encode_url(url)

    report = requests.get(
        f"{VT_URL}/{url_id}",
        headers=headers
    )

    data = report.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"]
    }
