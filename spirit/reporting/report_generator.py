from storage.database import get_scan_history


class ReportGenerator:

    def generate(self, report, path):
        history = get_scan_history(path)

        return {
            "scan_path": report.scan_path,
            "timestamp": report.timestamp,
            "score": report.score.to_dict(),
            "findings": [f.to_dict() for f in report.findings],
            "dependencies": [d.to_dict() for d in report.dependencies],
            "history": [
                {
                    "score": row[0],
                    "zone": row[1],
                    "findings_count": row[2],
                    "timestamp": row[3],
                }
                for row in history
            ],
            "trend": self._get_trend(history),
        }

    def _get_trend(self, history):
        if len(history) < 2:
            return "STABLE"

        # history is newest first
        latest = history[0][0]
        previous = history[1][0]

        diff = latest - previous

        if diff > 5:
            return "IMPROVING"
        elif diff < -5:
            return "DEGRADING"
        else:
            return "STABLE"
