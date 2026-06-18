class Comparator:

    def compare(self, declared_deps, actual_imports):
        declared = set(declared_deps)

        # clean actual imports
        builtins = {
            "fs",
            "path",
            "os",
            "http",
            "https",
            "crypto",
            "util",
            "events",
            "stream",
            "buffer",
            "url",
            "querystring",
            "child_process",
            "cluster",
            "net",
        }

        actual_external = set()
        for imp in actual_imports:
            if imp.startswith(".") or imp.startswith("/"):
                continue
            if imp in builtins:
                continue
            root = imp.split("/")[0]
            actual_external.add(root)

        ghost = declared - actual_external
        undeclared = actual_external - declared

        return {"ghost": list(ghost), "undeclared": list(undeclared)}
