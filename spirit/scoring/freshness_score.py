class FreshnessScorer:
    
    def compute(self, freshness_details_list):
        """
        Takes list of freshness detail dicts
        Returns 0-100 aggregate score
        """
        if not freshness_details_list:
            return 100.0
        
        valid = [d for d in freshness_details_list if d is not None]
        if not valid:
            return 100.0
        
        scores = [d["score"] for d in valid]
        return round(sum(scores) / len(scores), 1)