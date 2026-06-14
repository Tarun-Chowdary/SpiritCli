from datetime import datetime
from models import Finding, Dependency, Score, Report

class Engine:
    def __init__(self, path):
        self.path = path
        self.findings = []
        self.dependencies = []

    def run(self):
        from rich.console import Console
        from scoring import Calculator, ConfigScorer, TrustScorer, FreshnessScorer
        from storage.database import save_scan
        
        console = Console()

        # Step 1 - collect files
        files = self._collect_files()

        # Step 2 - collect dependencies
        self.dependencies = self._collect_dependencies()

        # Step 3 - config analysis
        self.findings = self._run_analysis(files)

        # Step 4 - CVE check
        console.print("[cyan]Checking CVEs...[/cyan]")
        cve_score, cve_findings = self._check_cves()
        self.findings.extend(cve_findings)

        # Step 5 - phantom check
        phantom_score, phantom_findings = self._check_phantom()
        self.findings.extend(phantom_findings)

        # Step 6 - compute all scores using dedicated scorers
        config_score = ConfigScorer().compute(self.findings)
        trust_score = TrustScorer().compute(self.dependencies)
        freshness_score = FreshnessScorer().compute(self.dependencies)

        calc = Calculator()
        score = calc.compute(
            config=config_score,
            cve=cve_score,
            trust=trust_score,
            freshness=freshness_score,
            phantom=phantom_score
        )

        # Step 7 - save to database
        save_scan(
            path=self.path,
            score=score.total,
            zone=score.zone,
            findings_count=len(self.findings)
        )

        # Step 8 - build and return report
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
                            deps.append(Dependency(
                                name=name.strip(),
                                version=version.strip()
                            ))
                        else:
                            deps.append(Dependency(
                                name=line,
                                version='unknown'
                            ))

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
            except Exception:
                pass

        return findings

    def _check_cves(self):
        from integrations.osv import OSVClient
        from scoring.cve_score import CVEScorer
        from storage.database import save_vulnerabilities

        client = OSVClient()
        scorer = CVEScorer()
        scores = []
        cve_findings = []

        for dep in self.dependencies:
            result = client.query(
                dep.name,
                dep.version.lstrip('^~'),
                "npm"
            )
            summary = client.get_cve_summary(result)
            dep_score = scorer.compute(summary)
            scores.append(dep_score)

            if summary["count"] > 0:
                vuln_list = [
                    {
                        "cve_id": cve_id,
                        "severity": "HIGH",
                        "description": f"{dep.name} vulnerability"
                    }
                    for cve_id in summary["ids"]
                ]
                save_vulnerabilities(
                    dep.name,
                    dep.version.lstrip('^~'),
                    vuln_list
                )

                severity = "critical" if summary["critical"] > 0 else "high"
                for cve_id in summary["ids"][:2]:
                    cve_findings.append(Finding(
                        severity=severity,
                        library=dep.name,
                        file="package.json",
                        line=0,
                        message=f"{cve_id} — {dep.name}@{dep.version}",
                        fix=f"Upgrade {dep.name} to latest version"
                    ))

        final_cve_score = round(
            sum(scores) / len(scores), 1
        ) if scores else 100.0
        return final_cve_score, cve_findings

    def _check_phantom(self):
        from phantom import PhantomDetector

        detector = PhantomDetector()
        result = detector.detect(self.path)
        phantom_score = detector.compute_score(result)
        phantom_findings = []

        for pkg in result["ghost"]:
            phantom_findings.append(Finding(
                severity="medium",
                library=pkg,
                file="package.json",
                line=0,
                message=f"Ghost dependency — {pkg} declared but never imported",
                fix=f"Remove {pkg} from package.json"
            ))

        for pkg in result["undeclared"]:
            phantom_findings.append(Finding(
                severity="high",
                library=pkg,
                file="package.json",
                line=0,
                message=f"Undeclared import — {pkg} used in code but not declared",
                fix=f"Add {pkg} to package.json dependencies"
            ))

        return phantom_score, phantom_findings