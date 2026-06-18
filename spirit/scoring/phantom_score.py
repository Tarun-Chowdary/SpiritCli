class PhantomScorer:

    def compute(self, phantom_result):
        """Takes phantom result dict, returns 0-100"""
        if not phantom_result:
            return 100.0

        ghost_count = len(phantom_result.get("ghost", []))
        undeclared_count = len(phantom_result.get("undeclared", []))

        ghost_penalty = ghost_count * 5
        undeclared_penalty = undeclared_count * 10

        total_penalty = ghost_penalty + undeclared_penalty
        return round(max(0, 100 - total_penalty), 1)
