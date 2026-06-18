import requests
import json
import os


class UpgradeEngine:

    def get_safe_version(self, package_name, current_version, cve_ids):
        try:
            response = requests.get(
                f"https://registry.npmjs.org/{package_name}", timeout=10
            )
            if response.status_code != 200:
                return None

            data = response.json()
            latest = data.get("dist-tags", {}).get("latest", "")
            versions = list(data.get("versions", {}).keys())
            versions = self._sort_versions(versions)

            clean_current = current_version.lstrip("^~v")

            try:
                current_idx = versions.index(clean_current)
                newer_versions = versions[current_idx + 1 :]
            except ValueError:
                newer_versions = versions

            if not newer_versions:
                return {
                    "current": clean_current,
                    "recommended": latest,
                    "latest": latest,
                    "reason": "Already at latest",
                }

            recommended = self._get_recommended(clean_current, newer_versions, latest)

            return {
                "current": clean_current,
                "recommended": recommended,
                "latest": latest,
                "reason": (
                    f"Fixes CVEs: {', '.join(cve_ids[:2])}"
                    if cve_ids
                    else "Outdated package"
                ),
            }

        except Exception:
            return None

    def _sort_versions(self, versions):
        def version_key(v):
            try:
                parts = v.lstrip("v").split("-")[0].split(".")
                return (
                    int(parts[0]),
                    int(parts[1]) if len(parts) > 1 else 0,
                    int(parts[2]) if len(parts) > 2 else 0,
                )
            except Exception:
                return (0, 0, 0)

        return sorted(versions, key=version_key)

    def _get_recommended(self, current, newer_versions, latest):
        try:
            current_major = int(current.split(".")[0])
            same_major = [
                v for v in newer_versions if int(v.split(".")[0]) == current_major
            ]
            if same_major:
                return same_major[-1]
            return latest
        except Exception:
            return latest

    def generate_upgrade_plan(self, dependencies, cve_findings):
        """Generate upgrade plan for all vulnerable packages"""
        plan = []

        # group CVEs by package
        cves_by_package = {}
        for finding in cve_findings:
            pkg = finding.library
            if pkg not in cves_by_package:
                cves_by_package[pkg] = []
            if "GHSA" in finding.message or "CVE" in finding.message:
                cve_id = finding.message.split("—")[0].strip()
                cves_by_package[pkg].append(cve_id)

        for dep in dependencies:
            if dep.name in cves_by_package:
                upgrade = self.get_safe_version(
                    dep.name, dep.version, cves_by_package[dep.name]
                )
                if upgrade and upgrade["current"] != upgrade["latest"]:
                    plan.append(
                        {
                            "package": dep.name,
                            "current": dep.version,
                            "recommended": upgrade["recommended"],
                            "latest": upgrade["latest"],
                            "cves": cves_by_package[dep.name],
                            "reason": upgrade["reason"],
                        }
                    )

        return plan

    def apply_upgrade(self, package_json_path, package_name, new_version):
        """
        Updates package.json with new version
        Returns True if successful
        """
        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)

            # backup first
            backup_path = package_json_path + ".spirit.bak"
            with open(backup_path, "w", encoding="utf-8") as f:
                json.dump(pkg_data, f, indent=2)

            # update version in dependencies
            updated = False
            if package_name in pkg_data.get("dependencies", {}):
                pkg_data["dependencies"][package_name] = f"^{new_version}"
                updated = True
            elif package_name in pkg_data.get("devDependencies", {}):
                pkg_data["devDependencies"][package_name] = f"^{new_version}"
                updated = True

            if updated:
                with open(package_json_path, "w", encoding="utf-8") as f:
                    json.dump(pkg_data, f, indent=2)
                return True

            return False

        except Exception as e:
            return False
