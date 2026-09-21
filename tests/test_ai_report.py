import json
from datetime import datetime

from analyzer.investigator import investigate_email
from analyzer.ai_report import generate_ai_report


EMAIL_PATH = "samples/phishing/test_phishing.eml"


print("\nRunning phishing investigation...\n")

investigation = investigate_email(
    EMAIL_PATH
)


print("\nGenerating AI analyst report...\n")

result = generate_ai_report(
    investigation
)


if result["status"] == "success":

    report = result["report"]

    # Save AI report as JSON
    report_data = {
        "generated_at": datetime.now().isoformat(),
        "report": report
    }

    with open(
        "reports/ai_analysis_report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        "\nAI report saved to "
        "reports/ai_analysis_report.json"
    )

    # Display AI report
    print("\n")
    print("=" * 70)
    print("             AI SOC ANALYST REPORT")
    print("=" * 70)

    print("\n[VERDICT]")
    print(report["verdict"])

    print("\n[CONFIDENCE]")
    print(report["confidence"])

    print("\n[EXECUTIVE SUMMARY]")
    print(report["executive_summary"])

    print("\n[KEY FINDINGS]")

    for finding in report["key_findings"]:
        print(f"- {finding}")

    print("\n[OBSERVED IOCs]")

    for ioc in report["observed_iocs"]:
        print(f"- {ioc}")

    print("\n[MITRE ATT&CK]")

    for technique in report["mitre_attack"]:
        print(f"- {technique}")

    print("\n[RECOMMENDED ACTIONS]")

    for action in report["recommended_actions"]:
        print(f"- {action}")

    print("\n[ANALYST NOTES]")
    print(report["analyst_notes"])

    print("\n")
    print("=" * 70)
    print("             AI ANALYSIS COMPLETE")
    print("=" * 70)


else:

    print("\nAI report generation failed:")
    print(result["message"])