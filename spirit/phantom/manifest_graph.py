import json
import os


class ManifestGraph:

    def build(self, path):
        """Build graph of all declared dependencies from package.json"""
        declared = []

        pkg_path = os.path.join(path, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path) as f:
                    pkg = json.load(f)
                declared.extend(pkg.get("dependencies", {}).keys())
                declared.extend(pkg.get("devDependencies", {}).keys())
            except Exception:
                pass

        return list(set(declared))
