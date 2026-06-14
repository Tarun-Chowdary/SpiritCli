# test_db.py
import sys
sys.path.insert(0, 'spirit')
from storage.database import get_scan_history

history = get_scan_history('demo_apps/vulnerable_bank_app')
for row in history:
    print(row)