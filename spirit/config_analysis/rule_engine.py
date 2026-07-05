import json
import os


class RuleEngine:
    def __init__(self):
        self.knowledge_base = {}
        self._load_rules()

    def _load_rules(self):
        kb_path = os.path.join(os.path.dirname(__file__), "knowledge_base")
        for filename in os.listdir(kb_path):
            if filename.endswith(".json"):
                with open(os.path.join(kb_path, filename)) as f:
                    data = json.load(f)
                    self.knowledge_base[filename.replace(".json", "")] = data

    def evaluate_bcrypt(self, extracted):
        findings = []
        rules = self.knowledge_base.get("bcrypt", {})
        methods = rules.get("methods", {})

        method = extracted.get("method")
        value = extracted.get("value")

        if method in methods:
            rule = methods[method]
            minimum = rule.get("minimum", 10)

            if isinstance(value, int) and value < minimum:
                message = rule["message"].replace("{value}", str(value))
                findings.append(
                    {
                        "severity": rule["severity"],
                        "library": "bcrypt",
                        "parameter": rule["parameter"],
                        "value": value,
                        "message": message,
                        "fix": f"Increase rounds to {rule['recommended']}",
                    }
                )

        return findings

    def evaluate_jwt(self, extracted):
        findings = []
        rules = self.knowledge_base.get("jwt", {})
        patterns = rules.get("patterns", {})

        if extracted.get("value") == "none":
            pattern = patterns.get("algorithm_none", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "critical"),
                    "library": "jwt",
                    "parameter": "algorithm",
                    "value": "none",
                    "message": pattern.get("message", "Unsafe JWT algorithm"),
                    "fix": "Set algorithm to HS256 or RS256",
                }
            )

        return findings

    def evaluate_axios(self, extracted):
        findings = []
        rules = self.knowledge_base.get("axios", {})
        patterns = rules.get("patterns", {})

        if extracted.get("value") == "false":
            pattern = patterns.get("reject_unauthorized", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "critical"),
                    "library": "axios",
                    "parameter": "rejectUnauthorized",
                    "value": "false",
                    "message": pattern.get("message", "TLS disabled"),
                    "fix": "Remove rejectUnauthorized:false or set to true",
                }
            )

        return findings

    def evaluate_mongoose(self, extracted):
        findings = []
        rules = self.knowledge_base.get("mongoose", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "strict" and value == "false":
            pattern = patterns.get("strict_false", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "high"),
                    "library": "mongoose",
                    "parameter": "strict",
                    "value": "false",
                    "message": pattern.get(
                        "message",
                        "Mongoose strict:false — allows arbitrary field injection",
                    ),
                    "fix": pattern.get("fix", "Remove strict:false or set strict:true"),
                }
            )

        elif parameter == "validation" and value == "missing":
            pattern = patterns.get("no_validation", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "medium"),
                    "library": "mongoose",
                    "parameter": "validation",
                    "value": "missing",
                    "message": pattern.get(
                        "message", "Mongoose schema missing validation"
                    ),
                    "fix": pattern.get(
                        "fix", "Add required:true and validation to schema fields"
                    ),
                }
            )

        return findings

    def evaluate_express(self, extracted):
        findings = []
        rules = self.knowledge_base.get("express", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "cors_origin" and value == "*":
            pattern = patterns.get("cors_wildcard", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "high"),
                    "library": "express",
                    "parameter": "cors_origin",
                    "value": "*",
                    "message": pattern.get(
                        "message", "CORS wildcard — allows any origin"
                    ),
                    "fix": "Restrict CORS to specific trusted origins",
                }
            )

        elif parameter == "helmet" and value == "missing":
            pattern = patterns.get("no_helmet", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "high"),
                    "library": "express",
                    "parameter": "helmet",
                    "value": "missing",
                    "message": pattern.get(
                        "message", "Express missing helmet — security headers not set"
                    ),
                    "fix": "Add helmet middleware: app.use(helmet())",
                }
            )

        return findings

    def evaluate_lodash(self, extracted):
        findings = []
        rules = self.knowledge_base.get("lodash", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "merge" and value == "user_input":
            pattern = patterns.get("merge_prototype", {})
            findings.append(
                {
                    "severity": pattern.get("severity", "critical"),
                    "library": "lodash",
                    "parameter": "merge",
                    "value": "user_input",
                    "message": pattern.get(
                        "message", "lodash.merge with user input — prototype pollution"
                    ),
                    "fix": "Use lodash.mergeWith with sanitized input or use spread operator",
                }
            )

        return findings
    
    def evaluate_requests(self, extracted):
        findings = []

        rules = self.knowledge_base.get("requests", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "verify" and value is False:
            pattern = patterns.get("verify_false", {})

            findings.append(
                {
                    "severity": pattern.get("severity", "critical"),
                    "library": "requests",
                    "parameter": "verify",
                    "value": False,
                    "message": pattern.get(
                        "message",
                        "SSL certificate verification is disabled."
                    ),
                    "fix": pattern.get(
                        "fix",
                        "Set verify=True"
                    ),
                }
            )

        return findings
    def evaluate_hashlib(self, extracted):
        findings = []

        rules = self.knowledge_base.get("hashlib", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "hash" and value == "md5":
            pattern = patterns.get("md5", {})

            findings.append({
                "severity": pattern.get("severity", "critical"),
                "library": "hashlib",
                "parameter": "hash",
                "value": "md5",
                "message": pattern.get(
                    "message",
                    "MD5 hashing detected -- cryptographically broken."
                ),
                "fix": "Use bcrypt or Argon2 instead of MD5."
            })

        return findings
    
    def evaluate_flask_cors(self, extracted):
        findings = []

        rules = self.knowledge_base.get("flask-cors", {})
        patterns = rules.get("patterns", {})

        parameter = extracted.get("parameter")
        value = extracted.get("value")

        if parameter == "cors_origin" and value == "*":
            pattern = patterns.get("cors_wildcard", {})

            findings.append({
                "severity": pattern.get("severity", "high"),
                "library": "flask-cors",
                "parameter": "cors_origin",
                "value": "*",
                "message": pattern.get(
                    "message",
                    "CORS wildcard (*) allows any origin."
                ),
                "fix": "Restrict CORS to trusted origins."
            })

        return findings