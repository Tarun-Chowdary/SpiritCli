import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spirit'))

from scoring.calculator import Calculator

def test_zero_score():
    calc = Calculator()
    score = calc.compute(0, 0, 0, 0, 0)
    assert score.total == 30.0
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

def test_perfect_score():
    calc = Calculator()
    score = calc.compute(100, 100, 100, 100, 100)
    assert score.total == 100.0
    assert score.zone == "SAFE"

def test_weighted_formula():
    calc = Calculator()
    score = calc.compute(
        config=100,
        cve=0,
        trust=100,
        freshness=100,
        phantom=100
    )
    # cve=0 becomes 30 due to floor
    # (100*0.30) + (30*0.25) + (100*0.20) + (100*0.15) + (100*0.10) = 82.5
    assert score.total == 82.5

def test_config_weight():
    calc = Calculator()
    score = calc.compute(
        config=0,
        cve=100,
        trust=100,
        freshness=100,
        phantom=100
    )
    # config=0 becomes 30 due to floor
    # (30*0.30) + (100*0.25) + (100*0.20) + (100*0.15) + (100*0.10) = 79.0
    assert score.total == 79.0

def test_score_rounded():
    calc = Calculator()
    score = calc.compute(33, 67, 50, 80, 90)
    assert isinstance(score.total, float)
    assert len(str(score.total).split('.')[-1]) <= 1