# test_freshness.py
import sys
sys.path.insert(0, 'spirit')
from integrations.npm_registry import NPMRegistry

registry = NPMRegistry()

packages = [
    ("lodash", "4.17.15"),
    ("axios", "0.21.1"),
    ("express", "4.17.1"),
    ("jsonwebtoken", "8.5.1"),
]

for name, version in packages:
    details = registry.get_freshness_details(name, version)
    if details:
        print(f"{name}: {details['current']} → {details['latest']} | Score: {details['score']}")
    else:
        print(f"{name}: could not fetch")