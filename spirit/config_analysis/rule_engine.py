import json
import os

class RuleEngine:
    def __init__(self):
        self.knowledge_base = {}
        self._load_rules()
    
    def _load_rules(self):
        kb_path = os.path.join(os.path.dirname(__file__), 'knowledge_base')
        for filename in os.listdir(kb_path):
            if filename.endswith('.json'):
                with open(os.path.join(kb_path, filename)) as f:
                    data = json.load(f)
                    self.knowledge_base[filename.replace('.json', '')] = data
    
    def evaluate_bcrypt(self, extracted):
        findings = []
        rules = self.knowledge_base.get('bcrypt', {})
        methods = rules.get('methods', {})
        
        method = extracted.get('method')
        value = extracted.get('value')
        
        if method in methods:
            rule = methods[method]
            minimum = rule.get('minimum', 10)
            
            if isinstance(value, int) and value < minimum:
                message = rule['message'].replace('{value}', str(value))
                findings.append({
                    "severity": rule['severity'],
                    "library": "bcrypt",
                    "parameter": rule['parameter'],
                    "value": value,
                    "message": message,
                    "fix": f"Increase rounds to {rule['recommended']}"
                })
        
        return findings
    
    def evaluate_jwt(self, extracted):
        findings = []
        rules = self.knowledge_base.get('jwt', {})
        patterns = rules.get('patterns', {})
        
        if extracted.get('value') == 'none':
            pattern = patterns.get('algorithm_none', {})
            findings.append({
                "severity": pattern.get('severity', 'critical'),
                "library": "jwt",
                "parameter": "algorithm",
                "value": "none",
                "message": pattern.get('message', 'Unsafe JWT algorithm'),
                "fix": "Set algorithm to HS256 or RS256"
            })
        
        return findings
    
    def evaluate_axios(self, extracted):
        findings = []
        rules = self.knowledge_base.get('axios', {})
        patterns = rules.get('patterns', {})
        
        if extracted.get('value') == 'false':
            pattern = patterns.get('reject_unauthorized', {})
            findings.append({
                "severity": pattern.get('severity', 'critical'),
                "library": "axios",
                "parameter": "rejectUnauthorized",
                "value": "false",
                "message": pattern.get('message', 'TLS disabled'),
                "fix": "Remove rejectUnauthorized:false or set to true"
            })
        
        return findings