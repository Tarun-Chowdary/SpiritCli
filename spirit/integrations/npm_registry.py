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
        """Returns 0-100 based on how outdated the package is"""
        try:
            info = self.get_package_info(package_name)
            if not info:
                return 70  # unknown, give neutral score
            
            latest = info.get("dist-tags", {}).get("latest", "")
            times = info.get("time", {})
            
            # compare major versions
            current_major = int(current_version.lstrip("^~").split(".")[0])
            latest_major = int(latest.split(".")[0])
            
            diff = latest_major - current_major
            
            if diff == 0:
                return 100
            elif diff == 1:
                return 75
            elif diff == 2:
                return 50
            else:
                return 25
                
        except Exception:
            return 70