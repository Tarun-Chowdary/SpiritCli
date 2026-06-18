class TyposquatDetector:

    # most popular npm packages that get typosquatted
    POPULAR_PACKAGES = [
        "express",
        "lodash",
        "axios",
        "react",
        "vue",
        "angular",
        "webpack",
        "babel",
        "jest",
        "mocha",
        "mongoose",
        "bcrypt",
        "jsonwebtoken",
        "dotenv",
        "moment",
        "chalk",
        "commander",
        "inquirer",
        "debug",
        "request",
        "async",
        "underscore",
        "bluebird",
        "q",
        "socket.io",
        "passport",
        "cors",
        "helmet",
        "morgan",
        "nodemon",
        "pm2",
        "sequelize",
        "knex",
        "typeorm",
        "redis",
        "mongodb",
        "mysql",
        "pg",
        "sqlite3",
    ]

    def check(self, package_name):
        """
        Returns dict with typosquatting risk assessment
        """
        result = {
            "package": package_name,
            "is_suspicious": False,
            "similar_to": None,
            "similarity_score": 0,
            "risk": "none",
        }

        # skip if it IS a popular package
        if package_name in self.POPULAR_PACKAGES:
            return result

        # check similarity against popular packages
        best_match = None
        best_score = 0

        for popular in self.POPULAR_PACKAGES:
            score = self._similarity(package_name, popular)
            if score > best_score:
                best_score = score
                best_match = popular

        result["similarity_score"] = round(best_score, 2)
        result["similar_to"] = best_match

        # flag if very similar but not identical
        if best_score >= 0.85 and package_name != best_match:
            result["is_suspicious"] = True
            result["risk"] = "critical"
        elif best_score >= 0.70 and package_name != best_match:
            result["is_suspicious"] = True
            result["risk"] = "high"
        elif best_score >= 0.60 and package_name != best_match:
            result["risk"] = "medium"

        return result

    def _similarity(self, s1, s2):
        """
        Levenshtein distance based similarity score
        Returns 0-1 where 1 is identical
        """
        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0

        # levenshtein distance matrix
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]

        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                matrix[i][j] = min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                )

        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)
