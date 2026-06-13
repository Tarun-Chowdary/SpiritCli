import re

class JSExtractor:
    
    def extract_all(self, source, filepath):
        results = []
        results.extend(self.extract_bcrypt(source))
        results.extend(self.extract_jwt(source))
        results.extend(self.extract_axios(source))
        return results
    
    def extract_bcrypt(self, source):
        findings = []
        pattern = r'\.hashSync\s*\([^,]+,\s*(\d+)\)'
        for match in re.finditer(pattern, source):
            findings.append({
                "library": "bcrypt",
                "method": "hashSync",
                "parameter": "rounds",
                "value": int(match.group(1)),
                "line": source[:match.start()].count('\n') + 1
            })
        return findings

    def extract_jwt(self, source):
        findings = []
        pattern = r'algorithm\s*:\s*["\']none["\']'
        for match in re.finditer(pattern, source):
            findings.append({
                "library": "jwt",
                "parameter": "algorithm",
                "value": "none",
                "line": source[:match.start()].count('\n') + 1
            })
        return findings

    def extract_axios(self, source):
        findings = []
        pattern = r'rejectUnauthorized\s*:\s*false'
        for match in re.finditer(pattern, source):
            findings.append({
                "library": "axios",
                "parameter": "rejectUnauthorized",
                "value": "false",
                "line": source[:match.start()].count('\n') + 1
            })
        return findings

    def extract_imports(self, source):
        imports = []
        pattern1 = r'require\s*\(["\']([^"\']+)["\']\)'
        pattern2 = r'import\s+.*?\s+from\s+["\']([^"\']+)["\']'
        for match in re.finditer(pattern1, source):
            imports.append(match.group(1))
        for match in re.finditer(pattern2, source):
            imports.append(match.group(1))
        return imports