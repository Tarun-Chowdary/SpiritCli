class TrustScorer:

    def compute(self, dependencies):
        """
        Basic trust scoring based on package metadata.
        Full provenance analysis is future scope.
        Returns 0-100
        """
        if not dependencies:
            return 100.0

        total = 0
        count = 0

        for dep in dependencies:
            score = 100

            # penalize unknown versions
            if dep.version in ["unknown", "", "*"]:
                score -= 20

            # penalize wildcard versions
            if dep.version.startswith("*"):
                score -= 15

            # use existing trust score if set
            if dep.trust_score is not None:
                score = dep.trust_score

            total += score
            count += 1

        return round(total / count, 1) if count > 0 else 100.0
