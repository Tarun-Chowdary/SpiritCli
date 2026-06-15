# test_provenance.py
import sys
sys.path.insert(0, 'spirit')
from provenance import TrustEngine

engine = TrustEngine()

packages = [
    ("lodash", "4.17.15"),
    ("axios", "0.21.1"),
    ("jsonwebtoken", "8.5.1"),
    ("express", "4.17.1"),
]

for name, version in packages:
    result = engine.analyze(name, version)
    print(f"\n{name}:")
    print(f"  Trust Score: {result['trust_score']}/100")
    print(f"  Risk Level: {result['risk_level']}")
    print(f"  Maintainers: {result['maintainer_count']}")
    print(f"  Age: {result['package_age_days']} days")
    print(f"  Last Update: {result['days_since_update']} days ago")
    print(f"  Typosquat Risk: {result['typosquat_risk']}")
    if result['signals']:
        for signal in result['signals']:
            print(f"  ⚠ {signal}")