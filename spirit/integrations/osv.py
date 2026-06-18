import requests


def fetch_vulnerabilities(package_name, version, ecosystem="npm"):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        raw_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] OSV API connection failed for {package_name}: {e}")
        return []

    cleaned_vulnerabilities = []
    if "vulns" in raw_data:
        for vuln in raw_data["vulns"]:
            cve_id = vuln.get("id", "UNKNOWN")
            description = vuln.get("summary", "No description provided.")
            db_specific = vuln.get("database_specific", {})
            severity = db_specific.get("severity", "UNKNOWN")
            cleaned_vulnerabilities.append(
                {"cve_id": cve_id, "severity": severity, "description": description}
            )
    return cleaned_vulnerabilities


class OSVClient:
    """Class wrapper so engine.py can use it cleanly"""

    def query(self, package_name, version, ecosystem="npm"):
        vulns = fetch_vulnerabilities(package_name, version, ecosystem)
        return {"vulns_cleaned": vulns}

    def get_cve_summary(self, osv_response):
        vulns = osv_response.get("vulns_cleaned", [])

        if not vulns:
            return {
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "ids": [],
            }

        summary = {
            "count": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "ids": [],
        }

        for vuln in vulns:
            summary["ids"].append(vuln["cve_id"])
            sev = vuln["severity"].upper()
            if sev == "CRITICAL":
                summary["critical"] += 1
            elif sev == "HIGH":
                summary["high"] += 1
            elif sev == "MODERATE" or sev == "MEDIUM":
                summary["medium"] += 1
            else:
                summary["low"] += 1

        return summary
