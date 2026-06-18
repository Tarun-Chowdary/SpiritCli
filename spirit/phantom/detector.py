import os
import json
import re
from .comparator import Comparator
from .import_graph import ImportGraph
from .manifest_graph import ManifestGraph


class PhantomDetector:

    def __init__(self):
        self.comparator = Comparator()
        self.import_graph = ImportGraph()
        self.manifest_graph = ManifestGraph()

    def detect(self, path):
        declared = self.manifest_graph.build(path)
        actual = self.import_graph.build(path)
        result = self.comparator.compare(declared, actual)
        return result

    def compute_score(self, phantom_result):
        ghost_count = len(phantom_result.get("ghost", []))
        undeclared_count = len(phantom_result.get("undeclared", []))

        ghost_penalty = ghost_count * 5
        undeclared_penalty = undeclared_count * 10

        total_penalty = ghost_penalty + undeclared_penalty
        return round(max(0, 100 - total_penalty), 1)
