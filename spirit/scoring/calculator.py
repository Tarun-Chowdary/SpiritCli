from models import Score


class Calculator:

    def compute(self, config=100, cve=100, trust=100, freshness=100, phantom=100):
        # apply minimum floor of 30 to each component
        config = max(30, config)
        cve = max(30, cve)
        trust = max(30, trust)
        freshness = max(30, freshness)
        phantom = max(30, phantom)

        total = (
            config * 0.30
            + cve * 0.25
            + trust * 0.20
            + freshness * 0.15
            + phantom * 0.10
        )

        zone = self._get_zone(total)

        return Score(
            config_score=round(config, 1),
            cve_score=round(cve, 1),
            trust_score=round(trust, 1),
            freshness_score=round(freshness, 1),
            phantom_score=round(phantom, 1),
            total=round(total, 1),
            zone=zone,
        )

    def _get_zone(self, total):
        if total >= 71:
            return "SAFE"
        elif total >= 40:
            return "WARNING"
        else:
            return "QUARANTINE"
