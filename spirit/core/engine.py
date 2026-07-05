"""SpiritCLI Core Engine — Central orchestration module"""

import os
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console

from models import Finding, Dependency, Score, Report
from storage.database import save_vulnerabilities

console = Console()


class Engine:
    """Main SpiritCLI scanning engine."""

    def __init__(self, path):
        self.path = path
        self.findings = []
        self.dependencies = []

    def run(self):
        """Run full security scan — all modules."""

        # Step 1 - collect files
        files = self._collect_files()
        console.print(f"[dim]Scanned {len(files)} files[/dim]")

        # Step 2 - collect dependencies
        self.dependencies = self._collect_dependencies()

        # Step 3 - config analysis
        self.findings = self._run_analysis(files)
        self.findings.extend(self._check_docker_hygiene())
        self.findings.extend(self._check_secrets())   

        # Step 4 - CVE check (parallel)
        try:
            cve_score, cve_findings = self._check_cves()
            self.findings.extend(cve_findings)
        except Exception as e:
            console.print(f"[yellow]CVE check failed: {e}[/yellow]")
            cve_score = 100.0
            
        try:
            docker_cve_score, docker_cve_findings = self._check_docker_cve()
            self.findings.extend(docker_cve_findings)

            # Equal-weight average with dependency CVE score. Documented choice:
            # OS-layer CVEs matter as much as dependency CVEs, not less.
            cve_score = round((cve_score + docker_cve_score) / 2, 1)

        except Exception as e:
            console.print(f"[yellow]Docker CVE check failed: {e}[/yellow]")

        # Step 5 - phantom check
        try:
            phantom_score, phantom_findings = self._check_phantom()
            self.findings.extend(phantom_findings)
        except Exception as e:
            console.print(f"[yellow]Phantom check failed: {e}[/yellow]")
            phantom_score = 100.0

        # Step 6 - freshness check (parallel)
        try:
            freshness_score, freshness_findings = self._check_freshness()
            self.findings.extend(freshness_findings)
        except Exception as e:
            console.print(f"[yellow]Freshness check failed: {e}[/yellow]")
            freshness_score = 100.0

        # Step 7 - provenance check
        try:
            trust_score, trust_findings = self._check_provenance()
            self.findings.extend(trust_findings)
        except Exception as e:
            console.print(f"[yellow]Provenance check failed: {e}[/yellow]")
            trust_score = 100.0

        # Step 8 - deduplicate
        self.findings = self._deduplicate_findings(self.findings)

        # Step 9 - compute score
        from scoring.calculator import Calculator
        calc = Calculator()
        score = calc.compute(
            config=self._get_config_score(),
            cve=cve_score,
            trust=trust_score,
            freshness=freshness_score,
            phantom=phantom_score,
        )

        # Step 10 - save to database
        try:
            from storage.database import save_scan
            save_scan(
                path=self.path,
                score=score.total,
                zone=score.zone,
                findings_count=len(self.findings),
            )
        except Exception as e:
            console.print(f"[yellow]Could not save scan: {e}[/yellow]")

        # Step 11 - build report
        report = Report(
            scan_path=self.path,
            findings=self.findings,
            dependencies=self.dependencies,
            score=score,
            timestamp=datetime.now().isoformat(),
        )
        

        return report

    # ── CACHE SYSTEM ────────────────────────────────────────

    def run_with_cache(self, force=False):
        """
        Run scan with caching.
        Returns cached result if files unchanged.
        Set force=True to bypass cache.
        """
        from storage.cache import get_cached_scan, save_scan_cache

        if not force:
            cached = get_cached_scan(self.path)
            if cached:
                console.print(
                    "[dim]⚡ Using cached scan — files unchanged[/dim]"
                )
                return self._deserialize_report(cached)

        report = self.run()
        save_scan_cache(self.path, self._serialize_report(report))
        return report

    def _serialize_report(self, report):
        """Convert report to JSON-serializable dict."""
        return {
            "scan_path": report.scan_path,
            "timestamp": report.timestamp,
            "findings": [f.to_dict() for f in report.findings],
            "dependencies": [d.to_dict() for d in report.dependencies],
            "score": report.score.to_dict(),
        }

    def _deserialize_report(self, data):
        """Rebuild Report object from cached dict."""
        findings = [
            Finding(
                severity=f["severity"],
                library=f["library"],
                file=f["file"],
                line=f["line"],
                message=f["message"],
                parameter=f.get("parameter"),
                value=f.get("value"),
                fix=f.get("fix"),
            )
            for f in data.get("findings", [])
        ]

        dependencies = [
            Dependency(
                name=d["name"],
                version=d["version"],
                is_direct=d.get("is_direct", True),
                is_dev=d.get("is_dev", False),
            )
            for d in data.get("dependencies", [])
        ]

        s = data.get("score", {})
        score = Score(
            config_score=s.get("config_score", 100),
            cve_score=s.get("cve_score", 100),
            trust_score=s.get("trust_score", 100),
            freshness_score=s.get("freshness_score", 100),
            phantom_score=s.get("phantom_score", 100),
            total=s.get("total", 100),
            zone=s.get("zone", "SAFE"),
        )

        return Report(
            scan_path=data["scan_path"],
            findings=findings,
            dependencies=dependencies,
            score=score,
            timestamp=data["timestamp"],
        )

    # ── FILE COLLECTION ─────────────────────────────────────

    def _collect_files(self):
        collected = []
        extensions = (".js", ".ts", ".py", ".jsx", ".tsx")

        # If the target is a single file
        if os.path.isfile(self.path):
            basename = os.path.basename(self.path)
            if self.path.endswith(extensions) or basename == "Dockerfile" or basename.startswith("Dockerfile."):
                collected.append(self.path)
            return collected

        # Otherwise scan the directory
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [
                d for d in dirs
                if d not in ["node_modules", "venv", ".git", "__pycache__"]
            ]
            for file in files:
                if file.endswith(extensions) or file == "Dockerfile" or file.startswith("Dockerfile."):
                    collected.append(os.path.join(root, file))

        return collected

    def _collect_dependencies(self):
        deps = []
        direct_names = set()

        pkg_path = os.path.join(self.path, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                for name, version in pkg.get("dependencies", {}).items():
                    deps.append(Dependency(name=name, version=version))
                    direct_names.add(name)
                for name, version in pkg.get("devDependencies", {}).items():
                    deps.append(
                        Dependency(name=name, version=version, is_dev=True)
                    )
                    direct_names.add(name)
            except Exception:
                pass

        # ── Transitive dependencies (package-lock.json) ──────────────────
        # Packages pulled in automatically by a direct dependency, but never
        # declared in package.json themselves. Invisible to CVE checking
        # otherwise, despite being real installed code. transitive_path
        # records the shortest chain from a direct dependency down to this
        # package (e.g. ["express", "qs"]) so findings can show *why* a
        # transitive package is installed, not just that it is.
        lock_path = os.path.join(self.path, "package-lock.json")
        if os.path.exists(lock_path):
            try:
                from integrations.lockfile import (
                    parse_transitive_dependencies,
                    build_dependency_graph,
                    find_dependency_chain,
                )
                transitive = parse_transitive_dependencies(lock_path, direct_names)
                graph, root_deps = build_dependency_graph(lock_path)
                for name, version in transitive:
                    chain = find_dependency_chain(graph, root_deps, name)
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        is_direct=False,
                        transitive_path=chain,
                    ))
            except Exception:
                pass

        req_path = os.path.join(self.path, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if "==" in line:
                                name, version = line.split("==", 1)
                                deps.append(
                                    Dependency(
                                        name=name.strip(),
                                        version=version.strip()
                                    )
                                )
                            else:
                                deps.append(
                                    Dependency(name=line, version="unknown")
                                )
            except Exception:
                pass

        return deps

    # ── CONFIG ANALYSIS ─────────────────────────────────────

    def _run_analysis(self, files):
        findings = []

        try:
            from ast_engine.extractors import JSExtractor
            from ast_engine.python_extractor import PythonExtractor
            from config_analysis import ConfigAnalyzer

            js_extractor = JSExtractor()
            py_extractor = PythonExtractor()
            analyzer = ConfigAnalyzer()

            for filepath in files:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        source = f.read()

                    configs = []

                    # JavaScript / TypeScript
                    if filepath.endswith((".js", ".ts", ".jsx", ".tsx")):
                        configs = js_extractor.extract_all(source, filepath)

                    # Python
                    elif filepath.endswith(".py"):
                        configs = py_extractor.extract_all(source, filepath)

                    # Skip unsupported files
                    else:
                        continue

                    file_findings = analyzer.analyze_file(filepath, configs)

                    if file_findings:
                        findings.extend(file_findings)

                except Exception:
                    # Continue scanning even if one file fails
                    continue

        except Exception:
            pass
        
        return findings

    # ── CVE CHECK — PARALLEL ────────────────────────────────

    def _check_cves(self):
        from integrations.osv import OSVClient
        from scoring.cve_score import CVEScorer
        from storage.database import save_vulnerabilities
        from storage.cache import get_cached_cve, save_cached_cve

        client = OSVClient()
        scorer = CVEScorer()
        scores = []
        cve_findings = []

        def check_single_dep(dep):
            """Check one dependency — runs in parallel thread."""
            try:
                clean_version = dep.version.lstrip("^~")

                cached = get_cached_cve(dep.name, clean_version)
                if cached:
                    return cached["score"], cached["findings_data"]

                result = client.query(dep.name, clean_version, "npm")
                summary = client.get_cve_summary(result)
                dep_score = scorer.compute(summary)
                findings_data = []

                if summary["count"] > 0:
                    vuln_list = [
                        {
                            "cve_id": cve_id,
                            "severity": "HIGH",
                            "description": f"{dep.name} vulnerability",
                        }
                        for cve_id in summary["ids"]
                    ]
                    try:
                        save_vulnerabilities(dep.name, clean_version, vuln_list)
                    except Exception:
                        pass

                    severity = "critical" if summary["critical"] > 0 else "high"
                    for cve_id in summary["ids"][:1]:
                        findings_data.append({
                            "severity": severity,
                            "library": dep.name,
                            "version": dep.version,
                            "cve_id": cve_id,
                            "transitive_path": dep.transitive_path,
                        })

                save_cached_cve(dep.name, clean_version, {
                    "score": dep_score,
                    "findings_data": findings_data,
                })

                return dep_score, findings_data

            except Exception:
                return 100.0, []

        # run all deps in parallel — 10 threads max
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_single_dep, dep): dep
                for dep in self.dependencies
            }
            for future in as_completed(futures):
                try:
                    dep_score, findings_data = future.result()
                    scores.append(dep_score)
                    for fd in findings_data:
                        chain = fd.get("transitive_path") or []
                        if len(chain) > 1:
                            via = " → ".join(chain[:-1])
                            message = f"{fd['cve_id']} — {fd['library']}@{fd['version']} (pulled in via {via})"
                        else:
                            message = f"{fd['cve_id']} — {fd['library']}@{fd['version']}"

                        cve_findings.append(Finding(
                            severity=fd["severity"],
                            library=fd["library"],
                            file="package.json",
                            line=0,
                            message=message,
                            fix=f"Upgrade {fd['library']} to latest version",
                        ))
                except Exception:
                    scores.append(100.0)

        final_cve_score = round(sum(scores) / len(scores), 1) if scores else 100.0
        return final_cve_score, cve_findings
    
    # ── DOCKER CVE CHECK ─────────────────────────────────────

    def _check_docker_cve(self):
        """Base-image / pinned-package CVEs. Feeds cve_score."""
        from integrations.docker_cve import extract_docker_cve

        findings = []
        for filepath in self._collect_files():
            if not os.path.basename(filepath).startswith("Dockerfile"):
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    contents = f.read()
                raw = extract_docker_cve(filepath, contents)
                for r in raw:
                    findings.append(Finding(
                        severity=r["severity"].lower(),
                        library=r.get("cve_id") or "docker-base-image",
                        file=r["file"],
                        line=r["line"],
                        message=r["message"],
                        fix=r["fix"],
                    ))
            except Exception:
                pass

        docker_cve_score = self._score_from_findings(findings)
        return docker_cve_score, findings

    # ── DOCKER HYGIENE CHECK ─────────────────────────────────

    def _check_docker_hygiene(self):
        """Dockerfile hygiene (root user, :latest, secrets in ENV, etc).
        Feeds config_score — same bucket as bcrypt/jwt/axios/mongoose/express/lodash."""
        from integrations.docker import extract_docker_config

        findings = []
        for filepath in self._collect_files():
            if not os.path.basename(filepath).startswith("Dockerfile"):
                continue
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    contents = f.read()
                raw = extract_docker_config(filepath, contents)
                for r in raw:
                    findings.append(Finding(
                        severity=r["severity"],
                        library="dockerfile",
                        file=r["file"],
                        line=r["line"],
                        message=r["message"],
                        fix=r["fix"],
                    ))
            except Exception:
                pass

        return findings

    # ── SHARED PENALTY SCORER (used by docker cve check) ────

    def _score_from_findings(self, findings):
        """Penalty curve for docker cve findings, intentionally lighter than
        _get_config_score's curve — averaged 50/50 with dependency CVE score,
        a single Dockerfile finding shouldn't swing cve_score as hard as the
        original 15/10/5/2 curve would."""
        if not findings:
            return 100.0
        penalty = 0
        for f in findings:
            if f.severity == "critical":
                penalty += 10
            elif f.severity == "high":
                penalty += 5
            elif f.severity == "medium":
                penalty += 3
            elif f.severity == "low":
                penalty += 1
        penalty = min(penalty, 70)
        return round(max(0, 100 - penalty), 1) 
    
    # ── PHANTOM CHECK ────────────────────────────────────────

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
                fix=f"Remove {pkg} from package.json",
            ))

        for pkg in result["undeclared"]:
            phantom_findings.append(Finding(
                severity="high",
                library=pkg,
                file="package.json",
                line=0,
                message=f"Undeclared import — {pkg} used in code but not declared",
                fix=f"Add {pkg} to package.json dependencies",
            ))

        return phantom_score, phantom_findings
    # ── SECRETS SCAN ─────────────────────────────────────────

    def _check_secrets(self):
        """Hardcoded credentials in source files (API keys, passwords,
        private keys, DB connection strings). Feeds config_score."""
        from integrations.secrets_scanner import scan_source

        findings = []
        for filepath in self._collect_files():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    contents = f.read()
                raw = scan_source(filepath, contents)
                for r in raw:
                    findings.append(Finding(
                        severity=r["severity"],
                        library="secrets",
                        file=r["file"],
                        line=r["line"],
                        message=r["message"],
                        fix=r["fix"],
                    ))
            except Exception:
                pass

        return findings
    
    def export_sbom_report(self, output_path="sbom.json"):
        """Generate a CycloneDX SBOM from currently-collected dependencies."""
        from reporting.sbom_exporter import export_sbom
        project_name = os.path.basename(os.path.abspath(self.path))
        return export_sbom(self.dependencies, output_path, project_name=project_name)
    # ── FRESHNESS CHECK — PARALLEL ───────────────────────────

    def _check_freshness(self):
        from integrations.npm_registry import NPMRegistry
        from scoring.freshness_score import FreshnessScorer
        from storage.cache import get_cached_freshness, save_cached_freshness

        registry = NPMRegistry()
        scorer = FreshnessScorer()
        details_list = []
        freshness_findings = []

        def check_single_dep(dep):
            """Check freshness for one dep — runs in parallel thread."""
            try:
                clean_version = dep.version.lstrip("^~v").strip()

                # check freshness cache first
                cached = get_cached_freshness(dep.name, clean_version)
                if cached:
                    return cached.get("details"), cached.get("finding_data")

                # not cached — query npm registry
                details = registry.get_freshness_details(dep.name, clean_version)
                finding_data = None

                if details and details["outdated"] and details["score"] < 70:
                    finding_data = {
                        "severity": "low" if details["score"] >= 60 else "medium",
                        "library": dep.name,
                        "current": details["current"],
                        "latest": details["latest"],
                        "transitive_path": dep.transitive_path,
                    }

                # save to freshness cache
                save_cached_freshness(dep.name, clean_version, {
                    "details": details,
                    "finding_data": finding_data,
                })

                return details, finding_data

            except Exception:
                return None, None

        # run all deps in parallel — 10 threads max
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_single_dep, dep): dep
                for dep in self.dependencies
            }
            for future in as_completed(futures):
                try:
                    details, finding_data = future.result()
                    details_list.append(details)
                    if finding_data:
                        chain = finding_data.get("transitive_path") or []
                        via_suffix = (
                            f" (pulled in via {' → '.join(chain[:-1])})"
                            if len(chain) > 1 else ""
                        )
                        freshness_findings.append(Finding(
                            severity=finding_data["severity"],
                            library=finding_data["library"],
                            file="package.json",
                            line=0,
                            message=(
                                f"{finding_data['library']} is outdated — "
                                f"current: {finding_data['current']} "
                                f"latest: {finding_data['latest']}{via_suffix}"
                            ),
                            fix=f"Upgrade {finding_data['library']} to {finding_data['latest']}",
                        ))
                except Exception:
                    details_list.append(None)

        freshness_score = scorer.compute(details_list)
        return freshness_score, freshness_findings

    # ── PROVENANCE CHECK ─────────────────────────────────────

    def _check_provenance(self):
        from provenance import TrustEngine

        engine = TrustEngine()
        analyses = engine.analyze_all(self.dependencies)
        trust_score = engine.compute_aggregate_score(analyses)
        trust_findings = []

        # lookup so transitive packages can show "(pulled in via ...)" —
        # analyses are plain dicts keyed by package name, not Dependency
        # objects, so we need this side table to get back to transitive_path
        path_by_name = {d.name: d.transitive_path for d in self.dependencies}

        for analysis in analyses:
            try:
                if analysis["risk_level"] in ["critical", "high"]:
                    severity = (
                        "critical"
                        if analysis["risk_level"] == "critical"
                        else "high"
                    )
                    chain = path_by_name.get(analysis["package"]) or []
                    via_suffix = (
                        f" (pulled in via {' → '.join(chain[:-1])})"
                        if len(chain) > 1 else ""
                    )
                    for signal in analysis["signals"][:1]:
                        trust_findings.append(Finding(
                            severity=severity,
                            library=analysis["package"],
                            file="package.json",
                            line=0,
                            message=f"[Trust] {signal}{via_suffix}",
                            fix=(
                                f"Review {analysis['package']} — "
                                f"trust score: {analysis['trust_score']}/100"
                            ),
                        ))
            except Exception:
                pass

        return trust_score, trust_findings

    # ── SCORING ──────────────────────────────────────────────

    def _get_config_score(self):
        if not self.findings:
            return 100.0

        config_libraries = [
            "bcrypt", "jwt", "jsonwebtoken",
            "axios", "mongoose", "express", "lodash", "requests","dockerfile", "secrets",
        ]

        config_findings = [
            f for f in self.findings
            if f.library in config_libraries and f.file != "package.json"
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

        penalty = min(penalty, 70)
        return round(max(0, 100 - penalty), 1)

    def _deduplicate_findings(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = (f.library, f.file, f.severity, f.message[:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── LICENSE CHECK ────────────────────────────────────────

    def _check_licenses(self):
        from integrations.license_api import LicenseChecker

        checker = LicenseChecker()
        results = checker.check_all(self.dependencies)
        license_score = checker.compute_score(results)
        license_findings = []

        for r in results:
            if r["status"] == "dangerous":
                license_findings.append(Finding(
                    severity="critical",
                    library=r["package"],
                    file="package.json",
                    line=0,
                    message=f"License {r['license']} incompatible with commercial use",
                    fix=f"Replace {r['package']} with MIT/Apache licensed alternative",
                ))
            elif r["status"] == "review":
                license_findings.append(Finding(
                    severity="medium",
                    library=r["package"],
                    file="package.json",
                    line=0,
                    message=f"License {r['license']} requires legal review",
                    fix=f"Review {r['package']} license with legal team",
                ))
            elif r["status"] == "unknown":
                license_findings.append(Finding(
                    severity="low",
                    library=r["package"],
                    file="package.json",
                    line=0,
                    message=f"License unknown for {r['package']} — review required",
                    fix=f"Verify license for {r['package']}",
                ))

        return license_score, license_findings