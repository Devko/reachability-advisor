import requests


def refresh_report_cache(report_id: str) -> dict:
    response = requests.get(f"https://reports.internal/api/reports/{report_id}", timeout=3)
    return response.json()
