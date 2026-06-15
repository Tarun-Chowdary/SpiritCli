import requests

class NPMRegistry:
    BASE_URL = "https://registry.npmjs.org"
    
    def get_package_info(self, package_name):
        try:
            response = requests.get(
                f"{self.BASE_URL}/{package_name}",
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None
    
    def get_latest_version(self, package_name):
        info = self.get_package_info(package_name)
        if info:
            return info.get("dist-tags", {}).get("latest", None)
        return None
    
    def get_freshness_score(self, package_name, current_version):
        """
        Compares current version against latest
        Returns 0-100 score
        """
        try:
            info = self.get_package_info(package_name)
            if not info:
                return 70  # unknown package, neutral score
            
            latest = info.get("dist-tags", {}).get("latest", "")
            if not latest:
                return 70
            
            # clean versions
            current = current_version.lstrip("^~v").strip()
            
            # parse major.minor.patch
            current_parts = self._parse_version(current)
            latest_parts = self._parse_version(latest)
            
            if not current_parts or not latest_parts:
                return 70
            
            current_major, current_minor, current_patch = current_parts
            latest_major, latest_minor, latest_patch = latest_parts
            
            # already on latest
            if current_major == latest_major and \
               current_minor == latest_minor and \
               current_patch == latest_patch:
                return 100.0
            
            # major version behind
            major_diff = latest_major - current_major
            if major_diff >= 3:
                return 20.0
            elif major_diff == 2:
                return 40.0
            elif major_diff == 1:
                return 60.0
            
            # minor version behind (same major)
            minor_diff = latest_minor - current_minor
            if minor_diff >= 5:
                return 70.0
            elif minor_diff >= 3:
                return 80.0
            elif minor_diff >= 1:
                return 90.0
            
            # only patch behind
            return 95.0
            
        except Exception:
            return 70.0
    
    def _parse_version(self, version_str):
        try:
            clean = version_str.lstrip("^~v").strip()
            # handle versions like 4.17.15-security
            clean = clean.split("-")[0]
            parts = clean.split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return major, minor, patch
        except Exception:
            return None
    
    def get_freshness_details(self, package_name, current_version):
        """Returns full details for reporting"""
        try:
            info = self.get_package_info(package_name)
            if not info:
                return None
            
            latest = info.get("dist-tags", {}).get("latest", "unknown")
            score = self.get_freshness_score(package_name, current_version)
            
            current = current_version.lstrip("^~v")
            
            return {
                "package": package_name,
                "current": current,
                "latest": latest,
                "score": score,
                "outdated": current != latest
            }
        except Exception:
            return None