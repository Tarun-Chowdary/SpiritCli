class CVEScorer:

    def compute(self, cve_summary):
        if cve_summary["count"] == 0:
            return 100.0

        # cap penalty at 40 per package so one bad package doesn't zero everything
        critical_penalty = min(cve_summary["critical"] * 25, 40)
        high_penalty = min(cve_summary["high"] * 10, 30)
        medium_penalty = min(cve_summary["medium"] * 5, 15)
        low_penalty = min(cve_summary["low"] * 2, 10)

        total_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty

        score = max(0, 100 - total_penalty)
        return round(score, 1)
