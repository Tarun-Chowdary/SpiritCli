import re
import os

class ImportGraph:
    
    def build(self, path):
        """Build graph of all actual imports from source code"""
        imports = []
        extensions = ('.js', '.ts', '.jsx', '.tsx')
        
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in
                      ['node_modules', 'venv', '.git', '__pycache__']]
            for file in files:
                if file.endswith(extensions):
                    filepath = os.path.join(root, file)
                    imports.extend(self._extract(filepath))
        
        return list(set(imports))  # deduplicate
    
    def _extract(self, filepath):
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
                    pkg = match.group(1)
                    # skip relative imports and builtins
                    if not pkg.startswith('.') and not pkg.startswith('/'):
                        root_pkg = pkg.split('/')[0]
                        imports.append(root_pkg)
        except Exception:
            pass
        
        return imports