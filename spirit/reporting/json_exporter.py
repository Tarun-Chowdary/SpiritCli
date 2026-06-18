import json
import os
from datetime import datetime


class JSONExporter:

    def export(self, report_data, output_path=None):
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"spirit_report_{timestamp}.json"

        with open(output_path, "w") as f:
            json.dump(report_data, f, indent=2)

        return output_path
