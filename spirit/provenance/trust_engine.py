from .registry_checker import RegistryChecker
from .typosquat import TyposquatDetector
from .maintainer_score import MaintainerScorer


class TrustEngine:

    def __init__(self):
        self.registry = RegistryChecker()
        self.typosquat = TyposquatDetector()
        self.maintainer_scorer = MaintainerScorer()

    def analyze(self, package_name, version):
        """
        Full provenance analysis for a single package
        Returns trust score 0-100 and signals
        """
        result = {
            "package": package_name,
            "version": version,
            "trust_score": 100.0,
            "risk_level": "low",
            "signals": [],
            "maintainer_count": 0,
            "package_age_days": 0,
            "days_since_update": 0,
            "typosquat_risk": "none",
        }

        # registry analysis
        registry_data = self.registry.analyze(package_name, version)

        if not registry_data:
            result["signals"].append("Could not fetch package data")
            result["trust_score"] = 50.0
            result["risk_level"] = "medium"
            return result

        result["maintainer_count"] = registry_data["maintainer_count"]
        result["package_age_days"] = registry_data["package_age_days"]
        result["days_since_update"] = registry_data["days_since_last_publish"]
        result["signals"].extend(registry_data["signals"])

        # typosquatting check
        typo_result = self.typosquat.check(package_name)
        result["typosquat_risk"] = typo_result["risk"]

        if typo_result["is_suspicious"]:
            result["signals"].append(
                f"Possible typosquatting — similar to '{typo_result['similar_to']}' "
                f"({int(typo_result['similarity_score'] * 100)}% similar)"
            )

        # compute trust score
        score = self._compute_score(registry_data, typo_result)
        result["trust_score"] = score

        # risk level
        if score >= 80:
            result["risk_level"] = "low"
        elif score >= 60:
            result["risk_level"] = "medium"
        elif score >= 40:
            result["risk_level"] = "high"
        else:
            result["risk_level"] = "critical"

        return result

    def _compute_score(self, registry_data, typo_result):
        score = 100.0

        # maintainer penalty
        maintainer_score = self.maintainer_scorer.compute(
            registry_data["maintainer_count"], registry_data["package_age_days"]
        )
        # maintainer contributes 35% of trust score
        score = score * 0.65 + maintainer_score * 0.35

        # package age penalty
        age_days = registry_data["package_age_days"]
        if age_days < 30:
            score -= 40
        elif age_days < 180:
            score -= 20
        elif age_days < 365:
            score -= 10

        # abandonment penalty
        days_inactive = registry_data["days_since_last_publish"]
        if days_inactive > 730:
            score -= 30
        elif days_inactive > 365:
            score -= 15
        elif days_inactive > 180:
            score -= 5

        # deprecation penalty
        if registry_data["is_deprecated"]:
            score -= 40

        # rapid releases penalty
        if registry_data["rapid_releases"]:
            score -= 20

        # typosquatting penalty
        if typo_result["risk"] == "critical":
            score -= 50
        elif typo_result["risk"] == "high":
            score -= 30
        elif typo_result["risk"] == "medium":
            score -= 10

        return round(max(0, min(100, score)), 1)

    def analyze_all(self, dependencies):
        """
        Analyze all dependencies
        Returns aggregate trust score and findings
        """
        results = []

        for dep in dependencies:
            clean_version = dep.version.lstrip("^~v").strip()
            analysis = self.analyze(dep.name, clean_version)
            results.append(analysis)

        return results

    def compute_aggregate_score(self, analyses):
        """
        Aggregate trust score across all packages
        Weighted — low scoring packages pull score down more
        """
        if not analyses:
            return 100.0

        scores = [a["trust_score"] for a in analyses]

        # weight: minimum score has 40% weight, average has 60%
        min_score = min(scores)
        avg_score = sum(scores) / len(scores)

        weighted = (min_score * 0.40) + (avg_score * 0.60)
        return round(weighted, 1)
