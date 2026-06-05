from dataclasses import dataclass, field
from typing import List
from .finding import Finding
from .score import Score
from .dependency import Dependency

@dataclass
class Report:
    scan_path: str
    findings: List[Finding] = field(default_factory=list)
    dependencies: List[Dependency] = field(default_factory=list)
    score: Score = None
    timestamp: str = ""

    def to_dict(self):
        return {
            "scan_path": self.scan_path,
            "findings": [f.to_dict() for f in self.findings],
            "dependencies": [d.to_dict() for d in self.dependencies],
            "score": self.score.to_dict() if self.score else None,
            "timestamp": self.timestamp
        }