import subprocess
import os


class DiffScanner:

    def get_changed_files(self, path="."):
        """Get files changed since last commit"""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                cwd=path,
                capture_output=True,
                text=True,
            )
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            return files
        except Exception:
            return []

    def get_staged_files(self, path="."):
        """Get files staged for commit"""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=path,
                capture_output=True,
                text=True,
            )
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            return files
        except Exception:
            return []

    def get_untracked_files(self, path="."):
        """Get new files not yet tracked by git"""
        try:
            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=path,
                capture_output=True,
                text=True,
            )
            files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
            return files
        except Exception:
            return []

    def get_all_changed(self, path="."):
        """Get all modified, staged, and new files"""
        changed = set()
        changed.update(self.get_changed_files(path))
        changed.update(self.get_staged_files(path))
        changed.update(self.get_untracked_files(path))

        # filter to only JS/TS/Python files
        extensions = (".js", ".ts", ".jsx", ".tsx", ".py", ".json")
        return [f for f in changed if f.endswith(extensions)]

    def scan_diff(self, path="."):
        """
        Scan only changed files
        Returns findings just for what changed
        """
        import sys

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

        from ast_engine.extractors import JSExtractor
        from config_analysis import ConfigAnalyzer
        from models import Finding

        changed_files = self.get_all_changed(path)

        if not changed_files:
            return [], []

        extractor = JSExtractor()
        analyzer = ConfigAnalyzer()
        findings = []

        for filepath in changed_files:
            full_path = os.path.join(path, filepath)
            if not os.path.exists(full_path):
                continue
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    source = f.read()
                configs = extractor.extract_all(source, full_path)
                file_findings = analyzer.analyze_file(full_path, configs)
                findings.extend(file_findings)
            except Exception:
                pass

        return findings, changed_files
