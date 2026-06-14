from datetime import datetime
from models import Finding, Dependency, Score, Report
from scoring import cve_score
from scoring.calculator import Calculator

class Engine:
    def __init__(self, path):
        self.path = path
        self.findings = []
        self.dependencies = []
        self.calculator = Calculator()

    def run(self):
        from rich.console import Console
        console = Console()
        
        files = self._collect_files()
        self.dependencies = self._collect_dependencies()
        self.findings = self._run_analysis(files)
        
        # add CVE check
        console.print("[cyan]Checking CVEs...[/cyan]")
        cve_score, cve_findings = self._check_cves()
        self.findings.extend(cve_findings)
        
        from scoring.calculator import Calculator
        calc = Calculator()
        score = calc.compute(
            config=self._get_config_score(),
            cve=cve_score,
            trust=100,
            freshness=100,
            phantom=100
        )
        # phantom check
        phantom_score, phantom_findings = self._check_phantom()
        self.findings.extend(phantom_findings)

        # update score with real phantom score
        score = calc.compute(
            config=self._get_config_score(),
            cve=cve_score,
            trust=100,
            freshness=100,
            phantom=phantom_score
        )
        # compute score with real CVE data
        
        
        from models import Report
        from datetime import datetime
        report = Report(
            scan_path=self.path,
            findings=self.findings,
            dependencies=self.dependencies,
            score=score,
            timestamp=datetime.now().isoformat()
        )
        from storage.database import save_scan, save_vulnerabilities
        save_scan(
            path=self.path,
            score=score.total,
            zone=score.zone,
            findings_count=len(self.findings)
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
    def _check_cves(self):
        from integrations.osv import OSVClient
        from scoring.cve_score import CVEScorer
        
        client = OSVClient()
        scorer = CVEScorer()
        
        scores = []
        cve_findings = []
        
        for dep in self.dependencies:
            ecosystem = "npm"
            result = client.query(dep.name, dep.version.lstrip('^~'), ecosystem)
            summary = client.get_cve_summary(result)
            
            dep_score = scorer.compute(summary)
            scores.append(dep_score)
            
            if summary["count"] > 0:
                from models import Finding
                severity = "critical" if summary["critical"] > 0 else "high"
                # only show top 2 CVEs per package to avoid noise
                for cve_id in summary["ids"][:2]:
                    cve_findings.append(Finding(
                        severity=severity,
                        library=dep.name,
                        file="package.json",
                        line=0,
                        message=f"{cve_id} — {dep.name}@{dep.version}",
                        fix=f"Upgrade {dep.name} to latest version"
                    ))
        
        # average across all packages
        final_cve_score = round(sum(scores) / len(scores), 1) if scores else 100.0
        return final_cve_score, cve_findings

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

    def _get_config_score(self):
        if not self.findings:
            return 100.0
        
        # these must match EXACTLY what your extractor sets as finding.library
        config_libraries = [
            'bcrypt', 
            'jwt',          
            'jsonwebtoken',  # add this
            'axios', 
            'mongoose',
            'express',
            'lodash'
        ]
        
        config_findings = [f for f in self.findings 
                        if f.library in config_libraries
                        and f.file != 'package.json']  # exclude CVE findings
        
        if not config_findings:
            return 100.0
        
        penalty = 0
        for f in config_findings:
            if f.severity == "critical":
                penalty += 25
            elif f.severity == "high":
                penalty += 15
            elif f.severity == "medium":
                penalty += 8
            elif f.severity == "low":
                penalty += 3
        
        return round(max(0, 100 - penalty), 1)
    def _check_phantom(self):
        import sys
        sys.path.insert(0, 'spirit')
        from phantom import PhantomDetector
        from models import Finding
        
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