from datetime import datetime
from models import Finding, Dependency, Score, Report

class Engine:
    def __init__(self, path):
        self.path = path
        self.findings = []
        self.dependencies = []

    def run(self):
        from scoring.calculator import Calculator
        from datetime import datetime
        from models import Report

        # Step 1 - collect files
        files = self._collect_files()

        # Step 2 - collect dependencies
        self.dependencies = self._collect_dependencies()

        # Step 3 - run config analysis
        self.findings = self._run_analysis(files)

        # Step 4 - CVE check
        cve_score, cve_findings = self._check_cves()
        self.findings.extend(cve_findings)

        # Step 5 - phantom check
        phantom_score, phantom_findings = self._check_phantom()
        self.findings.extend(phantom_findings)

        # Step 6 - freshness check
        freshness_score, freshness_findings = self._check_freshness()
        self.findings.extend(freshness_findings)

        # Step 7 - provenance check
        trust_score, trust_findings = self._check_provenance()
        self.findings.extend(trust_findings)

        # Step 8 - deduplicate findings
        seen = set()
        unique_findings = []
        for f in self.findings:
            key = (f.library, f.message[:50], f.file)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        self.findings = unique_findings

        # Step 9 - compute score
        calc = Calculator()
        score = calc.compute(
            config=self._get_config_score(),
            cve=cve_score,
            trust=trust_score,
            freshness=freshness_score,
            phantom=phantom_score
        )

        # Step 10 - save to database
        from storage.database import save_scan
        save_scan(
            path=self.path,
            score=score.total,
            zone=score.zone,
            findings_count=len(self.findings)
        )

        # Step 11 - build report
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

    def _check_freshness(self):
        from integrations.npm_registry import NPMRegistry
        from scoring.freshness_score import FreshnessScorer

        registry = NPMRegistry()
        scorer = FreshnessScorer()

        details_list = []
        freshness_findings = []

        for dep in self.dependencies:
            clean_version = dep.version.lstrip('^~v').strip()
            details = registry.get_freshness_details(dep.name, clean_version)
            details_list.append(details)

            if details and details["outdated"]:
                if details["score"] < 80:
                    freshness_findings.append(Finding(
                        severity="low" if details["score"] >= 60 else "medium",
                        library=dep.name,
                        file="package.json",
                        line=0,
                        message=(
                            f"{dep.name} is outdated — "
                            f"current: {details['current']} "
                            f"latest: {details['latest']}"
                        ),
                        fix=f"Upgrade {dep.name} to {details['latest']}"
                    ))

        freshness_score = scorer.compute(details_list)
        return freshness_score, freshness_findings

    def _check_provenance(self):
        from provenance import TrustEngine

        engine = TrustEngine()
        analyses = engine.analyze_all(self.dependencies)
        trust_score = engine.compute_aggregate_score(analyses)

        trust_findings = []

        for analysis in analyses:
            if analysis["risk_level"] in ["critical", "high"]:
                severity = "critical" if analysis["risk_level"] == "critical" else "high"
                for signal in analysis["signals"][:2]:
                    trust_findings.append(Finding(
                        severity=severity,
                        library=analysis["package"],
                        file="package.json",
                        line=0,
                        message=f"[Trust] {signal}",
                        fix=f"Review {analysis['package']} — trust score: {analysis['trust_score']}/100"
                    ))

            elif analysis["risk_level"] == "medium":
                for signal in analysis["signals"][:1]:
                    trust_findings.append(Finding(
                        severity="medium",
                        library=analysis["package"],
                        file="package.json",
                        line=0,
                        message=f"[Trust] {signal}",
                        fix=f"Monitor {analysis['package']} — trust score: {analysis['trust_score']}/100"
                    ))

        return trust_score, trust_findings

    def _get_config_score(self):
        """Convert config findings to 0-100 score"""
        if not self.findings:
            return 100.0

        config_libraries = [
            'bcrypt', 'jwt', 'jsonwebtoken',
            'axios', 'mongoose', 'express', 'lodash'
        ]

        config_findings = [
            f for f in self.findings
            if f.library in config_libraries
            and f.file != 'package.json'
        ]

        if not config_findings:
            return 100.0

        penalty = 0
        for f in config_findings:
            if f.severity == "critical":
                penalty += 15
            elif f.severity == "high":
                penalty += 10
            elif f.severity == "medium":
                penalty += 5
            elif f.severity == "low":
                penalty += 2

        # cap at 70 so score never goes below 30
        penalty = min(penalty, 70)

        return round(max(0, 100 - penalty), 1)