class RootCause:

    def analyze(self, path):
        history = []
        from storage.database import get_scan_history

        history = get_scan_history(path, limit=2)

        if len(history) < 2:
            return "Not enough scan history for root cause analysis."

        latest = history[0][0]
        previous = history[1][0]
        diff = latest - previous

        if diff > 0:
            return f"Score improved by {round(diff, 1)} points since last scan."
        elif diff < 0:
            return f"Score degraded by {round(abs(diff), 1)} points since last scan."
        else:
            return "Score unchanged since last scan."


# just a stub not built yet
