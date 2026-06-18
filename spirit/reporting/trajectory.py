from storage.database import get_scan_history


class Trajectory:

    def get(self, path):
        history = get_scan_history(path, limit=10)

        if not history:
            return None

        scores = [row[0] for row in history]
        scores.reverse()  # oldest first

        return {
            "scores": scores,
            "min": min(scores),
            "max": max(scores),
            "latest": scores[-1],
            "trend": self._classify(scores),
        }

    def _classify(self, scores):
        if len(scores) < 2:
            return "STABLE"
        diff = scores[-1] - scores[0]
        if diff > 5:
            return "IMPROVING"
        elif diff < -5:
            return "DEGRADING"
        else:
            return "STABLE"

    def ascii_graph(self, path):
        history = get_scan_history(path, limit=8)
        if not history:
            return ""

        scores = [row[0] for row in history]
        scores.reverse()

        lines = []
        lines.append("Score Trajectory")
        lines.append("")
        lines.append("100 |")
        lines.append(" 75 |")
        lines.append(" 50 |")
        lines.append(" 25 |")
        lines.append("  0 |" + "----" * len(scores))
        lines.append("     " + "  ".join([f"S{i+1}" for i in range(len(scores))]))
        lines.append("")
        lines.append("  " + "  ".join([str(s) for s in scores]))

        return "\n".join(lines)
