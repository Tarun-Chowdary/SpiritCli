from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    severity: str        # critical, high, medium, low
    library: str
    file: str
    line: int
    message: str
    parameter: Optional[str] = None
    value: Optional[str] = None
    fix: Optional[str] = None

    def to_dict(self):
        return {
            "severity": self.severity,
            "library": self.library,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "parameter": self.parameter,
            "value": str(self.value) if self.value is not None else None,
            "fix": self.fix
        }