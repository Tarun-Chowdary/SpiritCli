class FreshnessScorer:
    
    def compute(self, dependencies):
        """
        Checks npm registry for latest versions.
        Returns 0-100 based on how outdated packages are.
        """
        if not dependencies:
            return 100.0
        
        try:
            from integrations.npm_registry import NPMRegistry
            registry = NPMRegistry()
            
            scores = []
            for dep in dependencies:
                if dep.is_dev:
                    continue
                score = registry.get_freshness_score(
                    dep.name, 
                    dep.version.lstrip('^~')
                )
                scores.append(score)
            
            if not scores:
                return 100.0
            
            return round(sum(scores) / len(scores), 1)
        
        except Exception:
            return 80.0  # neutral fallback if registry unreachable