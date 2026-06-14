import os
import json
import re
from .comparator import Comparator

class PhantomDetector:
    
    def __init__(self):
        self.comparator = Comparator()
    
    def detect(self, path):
        declared = self._get_declared_deps(path)
        actual = self._get_actual_imports(path)
        result = self.comparator.compare(declared, actual)
        return result
    
    def _get_declared_deps(self, path):
        deps = []
        pkg_path = os.path.join(path, 'package.json')
        if os.path.exists(pkg_path):
            with open(pkg_path) as f:
                pkg = json.load(f)
            deps.extend(pkg.get('dependencies', {}).keys())
            deps.extend(pkg.get('devDependencies', {}).keys())
        return deps
    
    def _get_actual_imports(self, path):
        imports = []
        extensions = ('.js', '.ts', '.jsx', '.tsx')
        
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in
                      ['node_modules', 'venv', '.git', '__pycache__']]
            for file in files:
                if file.endswith(extensions):
                    filepath = os.path.join(root, file)
                    imports.extend(self._extract_imports(filepath))
        
        return imports
    
    def _extract_imports(self, filepath):
        imports = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source = f.read()
            
            patterns = [
                r'require\s*\(["\']([^"\']+)["\']\)',
                r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
                r'import\s*\(["\']([^"\']+)["\']\)'
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, source):
                    imports.append(match.group(1))
        except Exception:
            pass
        
        return imports
    
    def compute_score(self, phantom_result):
        ghost_count = len(phantom_result["ghost"])
        undeclared_count = len(phantom_result["undeclared"])
        
        ghost_penalty = ghost_count * 5
        undeclared_penalty = undeclared_count * 10
        
        total_penalty = ghost_penalty + undeclared_penalty
        return round(max(0, 100 - total_penalty), 1)