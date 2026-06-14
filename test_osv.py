# test_osv.py
import sys
sys.path.insert(0, 'spirit')

from integrations.osv import OSVClient

client = OSVClient()

# lodash 4.17.15 has known CVEs
result = client.query("lodash", "4.17.15", "npm")
summary = client.get_cve_summary(result)

print(f"CVEs found: {summary['count']}")
print(f"Critical: {summary['critical']}")
print(f"High: {summary['high']}")
print(f"IDs: {summary['ids']}")