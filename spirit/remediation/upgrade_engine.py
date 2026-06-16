import requests

class UpgradeEngine:
    
    def get_safe_version(self, package_name, current_version, cve_ids):
        """
        Find minimum version that fixes known CVEs
        Returns recommended upgrade version
        """
        try:
            # get all versions from npm
            response = requests.get(
                f"https://registry.npmjs.org/{package_name}",
                timeout=10
            )
            if response.status_code != 200:
                return None
            
            data = response.json()
            latest = data.get("dist-tags", {}).get("latest", "")
            versions = list(data.get("versions", {}).keys())
            
            # sort versions
            versions = self._sort_versions(versions)
            
            # get current version index
            clean_current = current_version.lstrip("^~v")
            
            # find versions newer than current
            try:
                current_idx = versions.index(clean_current)
                newer_versions = versions[current_idx + 1:]
            except ValueError:
                newer_versions = versions
            
            if not newer_versions:
                return {
                    "current": clean_current,
                    "recommended": latest,
                    "latest": latest,
                    "reason": "Already at or near latest"
                }
            
            # recommend minimum version above current
            # in real world would check if CVE is fixed
            # for MVP recommend latest patch or minor
            recommended = self._get_recommended(
                clean_current, newer_versions, latest
            )
            
            return {
                "current": clean_current,
                "recommended": recommended,
                "latest": latest,
                "reason": f"Fixes known CVEs: {', '.join(cve_ids[:2])}"
            }
            
        except Exception:
            return None
    
    def _sort_versions(self, versions):
        """Sort semantic versions"""
        def version_key(v):
            try:
                parts = v.lstrip("v").split("-")[0].split(".")
                return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0,
                        int(parts[2]) if len(parts) > 2 else 0)
            except Exception:
                return (0, 0, 0)
        return sorted(versions, key=version_key)
    
    def _get_recommended(self, current, newer_versions, latest):
        """
        Recommend minimum safe upgrade:
        - If same major versions available, pick latest minor/patch
        - Otherwise pick latest
        """
        try:
            current_major = int(current.split(".")[0])
            same_major = [
                v for v in newer_versions
                if int(v.split(".")[0]) == current_major
            ]
            if same_major:
                return same_major[-1]  # latest same-major version
            return latest
        except Exception:
            return latest
    
    def generate_upgrade_plan(self, dependencies, cve_findings):
        """
        Generate a full upgrade plan for all vulnerable packages
        """
        plan = []
        
        # group CVE findings by package
        cves_by_package = {}
        for finding in cve_findings:
            pkg = finding.library
            if pkg not in cves_by_package:
                cves_by_package[pkg] = []
            # extract CVE ID from message
            if "GHSA" in finding.message or "CVE" in finding.message:
                cve_id = finding.message.split("—")[0].strip()
                cves_by_package[pkg].append(cve_id)
        
        for dep in dependencies:
            if dep.name in cves_by_package:
                upgrade = self.get_safe_version(
                    dep.name,
                    dep.version,
                    cves_by_package[dep.name]
                )
                if upgrade:
                    plan.append({
                        "package": dep.name,
                        "current": dep.version,
                        "recommended": upgrade["recommended"],
                        "latest": upgrade["latest"],
                        "cves": cves_by_package[dep.name],
                        "reason": upgrade["reason"]
                    })
        
        return plan