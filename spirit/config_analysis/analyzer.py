import os
from models import Finding
from .rule_engine import RuleEngine


class ConfigAnalyzer:
    def __init__(self):
        self.rule_engine = RuleEngine()

    def analyze_file(self, filepath, extracted_configs):
        findings = []

        for config in extracted_configs:
            library = config.get("library")
            raw_findings = []

            if library == "bcrypt":
                raw_findings = self.rule_engine.evaluate_bcrypt(config)
            elif library == "jwt":
                raw_findings = self.rule_engine.evaluate_jwt(config)
            elif library == "axios":
                raw_findings = self.rule_engine.evaluate_axios(config)
            elif library == "mongoose":
                raw_findings = self.rule_engine.evaluate_mongoose(config)
            elif library == "express":
                raw_findings = self.rule_engine.evaluate_express(config)
            elif library == "lodash":
                raw_findings = self.rule_engine.evaluate_lodash(config)
            elif library == "requests":
                raw_findings = self.rule_engine.evaluate_requests(config)
            elif library == "hashlib":
                raw_findings = self.rule_engine.evaluate_hashlib(config)
            elif library == "flask-cors":
                raw_findings = self.rule_engine.evaluate_flask_cors(config)    
            for rf in raw_findings:
                findings.append(
                    Finding(
                        severity=rf["severity"],
                        library=rf["library"],
                        file=filepath,
                        line=config.get("line", 0),
                        message=rf["message"],
                        parameter=rf.get("parameter"),
                        value=str(rf.get("value", "")),
                        fix=rf.get("fix"),
                    )
                )

        return findings
