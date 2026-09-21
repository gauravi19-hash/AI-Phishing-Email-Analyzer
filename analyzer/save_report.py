import json
from datetime import datetime


def save_investigation_result(result, output_path):
    """
    Save the complete investigation result as JSON.
    """

    report = {
        "generated_at": datetime.now().isoformat(),
        "investigation": result
    }

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )