import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spirit'))

from scoring.calculator import Calculator

def test_perfect_score():
    calc = Calculator()
    score = calc.compute(100, 100, 100, 100, 100)
    assert score.total == 100.0
    assert score.zone == "SAFE"

def test_zero_score():
    calc = Calculator()
    score = calc.compute(0, 0, 0, 0, 0)
    assert score.total == 0.0
    assert score.zone == "QUARANTINE"

def test_safe_zone_boundary():
    calc = Calculator()
    score = calc.compute(71, 71, 71, 71, 71)
    assert score.zone == "SAFE"

def test_warning_zone():
    calc = Calculator()
    score = calc.compute(50, 50, 50, 50, 50)
    assert score.zone == "WARNING"

def test_quarantine_zone():
    calc = Calculator()
    score = calc.compute(20, 20, 20, 20, 20)
    assert score.zone == "QUARANTINE"

def test_weighted_formula():
    calc = Calculator()
    score = calc.compute(
        config=100,
        cve=0,
        trust=100,
        freshness=100,
        phantom=100
    )
    # cve weight is 25% so score should be 75
    assert score.total == 75.0

def test_config_weight():
    calc = Calculator()
    score = calc.compute(
        config=0,
        cve=100,
        trust=100,
        freshness=100,
        phantom=100
    )
    # config weight is 30% so score should be 70
    assert score.total == 70.0

def test_score_rounded():
    calc = Calculator()
    score = calc.compute(33, 67, 50, 80, 90)
    assert isinstance(score.total, float)
    assert len(str(score.total).split('.')[-1]) <= 1