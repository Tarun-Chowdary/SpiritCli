from datetime import datetime
from models import Finding, Dependency, Score, Report
from scoring.calculator import Calculator

class Engine:
    def __init__(self, path):
        self.path = path
        self.findings = []
        self.dependencies = []
        self.calculator = Calculator()

    def run(self):
        
        
        files = self._collect_files()
        

        self.dependencies = self._collect_dependencies()
        
        self.findings = self._run_analysis(files)
        
        score = self._compute_score()

        report = Report(
            scan_path=self.path,
            findings=self.findings,
            dependencies=self.dependencies,
            score=score,
            timestamp=datetime.now().isoformat()
        )

        return report

    def _collect_files(self):
        import os
        collected = []
        extensions = ('.js', '.ts', '.py', '.jsx', '.tsx')
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in
                      ['node_modules', 'venv', '.git', '__pycache__']]
            for file in files:
                if file.endswith(extensions):
                    collected.append(os.path.join(root, file))
        return collected

    def _collect_dependencies(self):
        import os
        import json
        deps = []

        pkg_path = os.path.join(self.path, 'package.json')
        if os.path.exists(pkg_path):
            with open(pkg_path) as f:
                pkg = json.load(f)
            for name, version in pkg.get('dependencies', {}).items():
                deps.append(Dependency(name=name, version=version))
            for name, version in pkg.get('devDependencies', {}).items():
                deps.append(Dependency(name=name, version=version, is_dev=True))

        req_path = os.path.join(self.path, 'requirements.txt')
        if os.path.exists(req_path):
            with open(req_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            name, version = line.split('==')
                            deps.append(Dependency(name=name.strip(),
                                                  version=version.strip()))
                        else:
                            deps.append(Dependency(name=line, version='unknown'))

        return deps

    def _run_analysis(self, files):
        findings = []

        from ast_engine.extractors import JSExtractor
        from config_analysis import ConfigAnalyzer

        extractor = JSExtractor()
        analyzer = ConfigAnalyzer()

        for filepath in files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    source = f.read()

                configs = extractor.extract_all(source, filepath)
                file_findings = analyzer.analyze_file(filepath, configs)
                findings.extend(file_findings)

            except Exception as e:
                pass

        return findings

    def _compute_score(self):
        critical = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        medium = sum(1 for f in self.findings if f.severity == "medium")

        config_score = 100.0
        config_score -= critical * 35
        config_score -= high * 15
        config_score -= medium * 7
        config_score = max(0, config_score)

        return self.calculator.compute(
            config=config_score,
            cve=100,
            trust=100,
            freshness=100,
            phantom=100
    )