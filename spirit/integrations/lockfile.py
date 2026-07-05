"""
integrations/lockfile.py — SpiritCLI transitive dependency parser

Direct dependencies come from package.json (see Engine._collect_dependencies).
This module reads package-lock.json to surface *transitive* dependencies —
packages pulled in automatically by something you declared, but never
declared yourself. Those don't show up in package.json at all, so without
this they're invisible to CVE checking despite being real, installed code.

Supports both lockfile formats npm has used:
  - lockfileVersion 2/3 ("packages" key, flat path-keyed map)
  - lockfileVersion 1  ("dependencies" key, recursively nested)

Deliberately lightweight: we report every resolved package/version found
in the lockfile beyond the direct set. We do not attempt full dependency
*graph* reconstruction (who-depends-on-whom) — for CVE purposes, knowing
"this version of this package is installed" is what matters; the graph
itself is a nice-to-have for a later pass, not needed for scoring.
"""

import json
from collections import deque


def build_dependency_graph(lockfile_path):
    """
    Build a directed graph of "who requires whom" from package-lock.json.
    Returns (graph, root_deps) where:
      - graph: {package_name: set(package_names it directly requires)}
      - root_deps: set of package names required directly by the project
                   (i.e. package.json's own dependencies, as recorded in
                   the lockfile's root entry)

    Returns ({}, set()) on any parse failure — callers should treat a
    missing graph as "chain unknown", not crash.
    """
    try:
        with open(lockfile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}, set()

    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 2 and "packages" in data:
        return _build_graph_v2_v3(data)
    elif "dependencies" in data:
        return _build_graph_v1(data)
    return {}, set()


def _build_graph_v2_v3(data):
    graph = {}
    root_deps = set()
    packages = data.get("packages", {})

    root_entry = packages.get("", {})
    root_deps.update(root_entry.get("dependencies", {}).keys())
    root_deps.update(root_entry.get("devDependencies", {}).keys())

    for pkg_path, meta in packages.items():
        if pkg_path == "":
            continue
        if "node_modules/" not in pkg_path:
            continue
        name = pkg_path.rsplit("node_modules/", 1)[-1]
        required = set(meta.get("dependencies", {}).keys())
        graph.setdefault(name, set()).update(required)

    return graph, root_deps


def _build_graph_v1(data):
    graph = {}
    root_deps = set(data.get("dependencies", {}).keys())

    def walk(deps_dict):
        for name, meta in deps_dict.items():
            required = set(meta.get("requires", {}).keys())
            graph.setdefault(name, set()).update(required)
            nested = meta.get("dependencies")
            if nested:
                walk(nested)

    walk(data.get("dependencies", {}))
    return graph, root_deps


def find_dependency_chain(graph, root_deps, target_package):
    """
    BFS from the set of direct/root dependencies down to target_package.
    Returns the shortest chain as a list, e.g. ["express", "body-parser", "qs"]
    (target_package itself included as the last element), or [] if
    target_package is unreachable from any root dependency (or is itself
    a root dependency, or the graph is empty/malformed).
    """
    if not graph or target_package in root_deps:
        return []

    visited = set(root_deps)
    queue = deque()
    for root in root_deps:
        queue.append([root])
        visited.add(root)

    while queue:
        path = queue.popleft()
        current = path[-1]
        for child in graph.get(current, ()):
            if child == target_package:
                return path + [child]
            if child not in visited:
                visited.add(child)
                queue.append(path + [child])

    return []


def parse_transitive_dependencies(lockfile_path, direct_names):
    """
    lockfile_path: path to package-lock.json
    direct_names: set of package names already known from package.json —
                  anything in the lockfile NOT in this set is transitive.

    Returns a list of (name, version) tuples for transitive dependencies
    only. Returns [] on any parse failure — a missing/malformed lockfile
    should never break the rest of the scan.
    """
    try:
        with open(lockfile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 2 and "packages" in data:
        return _parse_v2_v3(data, direct_names)
    elif "dependencies" in data:
        return _parse_v1(data, direct_names)
    return []


def _parse_v2_v3(data, direct_names):
    found = {}
    for pkg_path, meta in data.get("packages", {}).items():
        if pkg_path == "":
            continue  # the root project entry itself, not a dependency
        if "node_modules/" not in pkg_path:
            continue
        # last node_modules/ segment gives the actual package name, so
        # nested transitive copies (node_modules/a/node_modules/b) resolve
        # to "b", not the full nested path
        name = pkg_path.rsplit("node_modules/", 1)[-1]
        version = meta.get("version")
        if not version:
            continue
        if name in direct_names:
            continue
        found[name] = version  # last write wins if the same package
                                # appears at multiple nested paths/versions
    return list(found.items())


def _parse_v1(data, direct_names):
    found = {}

    def walk(deps_dict):
        for name, meta in deps_dict.items():
            version = meta.get("version")
            if version and name not in direct_names:
                found[name] = version
            nested = meta.get("dependencies")
            if nested:
                walk(nested)

    walk(data.get("dependencies", {}))
    return list(found.items())