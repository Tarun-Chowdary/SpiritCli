class MaintainerScorer:

    def compute(self, maintainer_count, package_age_days):
        """
        Returns 0-100 score based on maintainer health
        """
        if maintainer_count == 0:
            return 0.0

        if maintainer_count == 1:
            # single maintainer is risky
            # but if package is very old and stable, slightly less risky
            if package_age_days > 1825:  # 5 years
                return 40.0
            elif package_age_days > 730:  # 2 years
                return 30.0
            else:
                return 20.0

        elif maintainer_count == 2:
            return 65.0

        elif maintainer_count <= 5:
            return 80.0

        elif maintainer_count <= 10:
            return 90.0

        else:
            return 100.0
