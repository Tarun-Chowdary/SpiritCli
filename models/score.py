from dataclasses import dataclass

@dataclass
class Score:
    config_score: float = 100.0
    cve_score: float = 100.0
    trust_score: float = 100.0
    freshness_score: float = 100.0
    phantom_score: float = 100.0
    total: float = 100.0
    zone: str = "SAFE"

    def to_dict(self):
        return {
            "config_score": self.config_score,
            "cve_score": self.cve_score,
            "trust_score": self.trust_score,
            "freshness_score": self.freshness_score,
            "phantom_score": self.phantom_score,
            "total": round(self.total, 1),
            "zone": self.zone
        }