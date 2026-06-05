from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Dependency:
    name: str
    version: str
    is_direct: bool = True
    is_dev: bool = False
    transitive_path: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    trust_score: Optional[int] = None

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "transitive_path": self.transitive_path,
            "cves": self.cves,
            "trust_score": self.trust_score
        }