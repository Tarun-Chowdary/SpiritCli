import re

class JSExtractor:
    
    def extract_all(self, source_code, filepath):
        results = []
        results.extend(self.extract_bcrypt(source_code))
        results.extend(self.extract_jwt(source_code))
        results.extend(self.extract_axios(source_code))
        results.extend(self.extract_express(source_code))
        results.extend(self.extract_mongoose(source_code))
        results.extend(self.extract_lodash(source_code))
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
    
    def extract_express(self, source):
        findings = []
        
        # check for cors wildcard
        pattern = r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*["\']?'
        for match in re.finditer(pattern, source):
            findings.append({
                "library": "express",
                "parameter": "cors_origin",
                "value": "*",
                "line": source[:match.start()].count('\n') + 1
            })
        
        # check for missing helmet (if express imported but helmet never mentioned)
        if 'require("express")' in source or "require('express')" in source:
            if 'helmet' not in source:
                findings.append({
                    "library": "express",
                    "parameter": "helmet",
                    "value": "missing",
                    "line": 1
                })
        
        return findings

    def extract_mongoose(self, source):
        findings = []
        
        # strict: false
        pattern1 = r'strict\s*:\s*false'
        for match in re.finditer(pattern1, source):
            findings.append({
                "library": "mongoose",
                "parameter": "strict",
                "value": "false",
                "line": source[:match.start()].count('\n') + 1
            })
        
        # new mongoose.Schema without validation
        pattern2 = r'new\s+mongoose\.Schema\s*\(\s*\{'
        for match in re.finditer(pattern2, source):
            # check if required or validation is missing nearby
            nearby = source[match.start():match.start()+200]
            if 'required' not in nearby and 'validate' not in nearby:
                findings.append({
                    "library": "mongoose",
                    "parameter": "validation",
                    "value": "missing",
                    "line": source[:match.start()].count('\n') + 1
                })
        
        return findings

    def extract_lodash(self, source):
        findings = []
        
        # lodash.merge with req.body or user input — prototype pollution
        pattern = r'(?:lodash|_)\.merge\s*\([^)]*(?:req\.|body|params|query|user)'
        for match in re.finditer(pattern, source, re.IGNORECASE):
            findings.append({
                "library": "lodash",
                "parameter": "merge",
                "value": "user_input",
                "line": source[:match.start()].count('\n') + 1
            })
        
        return findings