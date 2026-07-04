class ConfigScorer:

    def compute(self, findings):
        """Takes list of Finding objects, returns 0-100"""
        config_libraries = [
            "bcrypt",
            "jwt",
            "jsonwebtoken",
            "axios",
            "mongoose",
            "express",
            "lodash",
            "hashlib",
            "flask-cors",
        ]

        config_findings = [
            f
            for f in findings
            if f.library in config_libraries and f.file != "package.json"
        ]

        if not config_findings:
            return 100.0

        penalty = 0
        for f in config_findings:
            if f.severity == "critical":
                penalty += 25
            elif f.severity == "high":
                penalty += 15
            elif f.severity == "medium":
                penalty += 8
            elif f.severity == "low":
                penalty += 3

        return round(max(0, 100 - penalty), 1)
