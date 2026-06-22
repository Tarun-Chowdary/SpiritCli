class TrustScorer:
    def compute(self, dependencies):
        """
        Advanced trust scoring based on provenance, maintainer reputation, 
        and repository health. Returns 0-100.
        """
        if not dependencies:
            return 100.0

        total_score = 0

        for dep in dependencies:
            # this version shifts the paradigm: Start at a neutral 50, require proof to reach 100
            score = 50.0  

            # 1. Versioning Sanity (Retained from MVP)
            if dep.version in ["unknown", "", "*"]:
                score -= 20
            elif dep.version.startswith("*"):
                score -= 10

            # 2. Maintainer Identity & Provenance (New)
            if getattr(dep, 'is_verified_publisher', False):
                score += 25  # E.g., npm verified publisher
            if getattr(dep, 'has_2fa_enabled', False):
                score += 15  # Protection against account takeovers

            # 3. Community Adoption & Health (New)
            stars = getattr(dep, 'github_stars', 0)
            if stars > 5000:
                score += 10
            elif stars > 500:
                score += 5

            # 4. Critical Supply Chain Red Flags (New)
            if getattr(dep, 'is_deprecated', False):
                score -= 40  # Massive penalty: package is officially abandoned
            if getattr(dep, 'has_recent_ownership_transfer', False):
                score -= 25  # High risk of malicious takeover (e.g., standard supply chain attack)

            # Enforce 0-100 boundaries
            score = max(0.0, min(100.0, score))

            # Allow external hard-override (if another security tool already vetted it)
            if getattr(dep, 'trust_score', None) is not None:
                score = dep.trust_score

            total_score += score

        return round(total_score / len(dependencies), 1)
