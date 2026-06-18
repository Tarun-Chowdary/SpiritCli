import requests
from datetime import datetime, timezone


class RegistryChecker:
    BASE_URL = "https://registry.npmjs.org"

    def get_package_data(self, package_name):
        try:
            response = requests.get(f"{self.BASE_URL}/{package_name}", timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def analyze(self, package_name, current_version):
        data = self.get_package_data(package_name)
        if not data:
            return None

        result = {
            "package": package_name,
            "version": current_version,
            "maintainer_count": 0,
            "package_age_days": 0,
            "days_since_last_publish": 0,
            "weekly_downloads": 0,
            "total_versions": 0,
            "rapid_releases": False,
            "is_deprecated": False,
            "signals": [],
        }

        # maintainer count
        maintainers = data.get("maintainers", [])
        result["maintainer_count"] = len(maintainers)

        # package age
        time_data = data.get("time", {})
        created_str = time_data.get("created", "")
        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                result["package_age_days"] = (now - created).days
            except Exception:
                pass

        # days since last publish
        modified_str = time_data.get("modified", "")
        if modified_str:
            try:
                modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                result["days_since_last_publish"] = (now - modified).days
            except Exception:
                pass

        # total versions
        versions = data.get("versions", {})
        result["total_versions"] = len(versions)

        # rapid releases — more than 20 versions in last 30 days
        recent_releases = 0
        now = datetime.now(timezone.utc)
        for version_time in time_data.values():
            if version_time in ("created", "modified"):
                continue
            try:
                vt = datetime.fromisoformat(str(version_time).replace("Z", "+00:00"))
                if (now - vt).days <= 30:
                    recent_releases += 1
            except Exception:
                pass
        result["rapid_releases"] = recent_releases > 20

        # deprecated check
        latest = data.get("dist-tags", {}).get("latest", "")
        if latest and latest in versions:
            deprecated = versions[latest].get("deprecated", "")
            result["is_deprecated"] = bool(deprecated)
            if deprecated:
                result["signals"].append(f"Package deprecated: {deprecated}")

        # build signals
        if result["maintainer_count"] == 1:
            result["signals"].append("Single maintainer — high bus factor risk")
        elif result["maintainer_count"] == 0:
            result["signals"].append("No maintainers listed — abandoned")

        if result["package_age_days"] < 30:
            result["signals"].append("Package less than 30 days old — very new")
        elif result["package_age_days"] < 180:
            result["signals"].append("Package less than 6 months old — relatively new")

        if result["days_since_last_publish"] > 730:
            result["signals"].append(
                f"No updates in {result['days_since_last_publish'] // 365} years — possibly abandoned"
            )
        elif result["days_since_last_publish"] > 365:
            result["signals"].append(
                f"No updates in {result['days_since_last_publish']} days"
            )

        if result["rapid_releases"]:
            result["signals"].append(
                f"Unusual release frequency — {recent_releases} versions in 30 days"
            )

        return result
