import requests

# Known safe licenses for commercial banking use
SAFE_LICENSES = {
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "CC0-1.0",
    "Unlicense",
    "0BSD",
}

# Licenses that need legal review
REVIEW_LICENSES = {
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MPL-2.0",
    "CDDL-1.0",
    "EPL-1.0",
    "EPL-2.0",
}

# Licenses incompatible with commercial use
DANGEROUS_LICENSES = {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "GPL-2.0-only",
    "GPL-3.0-only",
    "AGPL-3.0-only",
}


class LicenseChecker:

    def get_license(self, package_name):
        """Get license for an npm package"""
        try:
            response = requests.get(
                f"https://registry.npmjs.org/{package_name}/latest", timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                license_info = data.get("license", "UNKNOWN")

                # handle dict format
                if isinstance(license_info, dict):
                    license_info = license_info.get("type", "UNKNOWN")

                return license_info
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    def evaluate_license(self, license_str):
        """
        Returns: safe, review, dangerous, unknown
        """
        if not license_str or license_str == "UNKNOWN":
            return "unknown"

        # normalize
        license_str = license_str.strip()

        if license_str in SAFE_LICENSES:
            return "safe"
        elif license_str in REVIEW_LICENSES:
            return "review"
        elif license_str in DANGEROUS_LICENSES:
            return "dangerous"
        else:
            return "unknown"

    def check_all(self, dependencies):
        """Check licenses for all dependencies"""
        results = []

        for dep in dependencies:
            license_str = self.get_license(dep.name)
            status = self.evaluate_license(license_str)

            results.append(
                {
                    "package": dep.name,
                    "version": dep.version,
                    "license": license_str,
                    "status": status,
                }
            )

        return results

    def compute_score(self, results):
        """Returns 0-100 license compliance score"""
        if not results:
            return 100.0

        penalty = 0
        for r in results:
            if r["status"] == "dangerous":
                penalty += 30
            elif r["status"] == "review":
                penalty += 10
            elif r["status"] == "unknown":
                penalty += 5

        return round(max(0, 100 - penalty), 1)
