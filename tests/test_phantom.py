import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spirit'))

from phantom.comparator import Comparator

def test_ghost_dependency_detected():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash", "axios", "xml-parser"],
        actual_imports=["lodash", "axios"]
    )
    assert "xml-parser" in result["ghost"]

def test_undeclared_import_detected():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash"],
        actual_imports=["lodash", "moment"]
    )
    assert "moment" in result["undeclared"]

def test_clean_project_no_phantom():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash", "axios"],
        actual_imports=["lodash", "axios"]
    )
    assert len(result["ghost"]) == 0
    assert len(result["undeclared"]) == 0

def test_relative_imports_ignored():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash"],
        actual_imports=["lodash", "./utils", "../config", "/absolute"]
    )
    assert "./utils" not in result["undeclared"]
    assert "../config" not in result["undeclared"]
    assert "/absolute" not in result["undeclared"]

def test_node_builtins_ignored():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash"],
        actual_imports=["lodash", "fs", "path", "os", "crypto", "http"]
    )
    assert "fs" not in result["undeclared"]
    assert "path" not in result["undeclared"]
    assert "os" not in result["undeclared"]

def test_multiple_ghost_deps():
    comp = Comparator()
    result = comp.compare(
        declared_deps=["lodash", "axios", "moment", "xml-parser"],
        actual_imports=["lodash"]
    )
    assert "axios" in result["ghost"]
    assert "moment" in result["ghost"]
    assert "xml-parser" in result["ghost"]

def test_phantom_score_clean():
    from phantom.detector import PhantomDetector
    detector = PhantomDetector()
    result = {"ghost": [], "undeclared": []}
    score = detector.compute_score(result)
    assert score == 100.0

def test_phantom_score_with_ghost():
    from phantom.detector import PhantomDetector
    detector = PhantomDetector()
    result = {"ghost": ["xml-parser", "moment"], "undeclared": []}
    score = detector.compute_score(result)
    assert score == 90.0  # 2 ghost deps * 5 penalty each

def test_phantom_score_with_undeclared():
    from phantom.detector import PhantomDetector
    detector = PhantomDetector()
    result = {"ghost": [], "undeclared": ["moment"]}
    score = detector.compute_score(result)
    assert score == 90.0  # 1 undeclared * 10 penalty