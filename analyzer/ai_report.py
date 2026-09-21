import os
import json
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI


# Always load the .env file from the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def generate_ai_report(investigation):
    """
    Generate a SOC-style analyst report from structured
    phishing investigation evidence.
    """

    if not OPENAI_API_KEY:
        return {
            "status": "error",
            "message": "OpenAI API key not configured."
        }

    try:

        client = OpenAI(
            api_key=OPENAI_API_KEY
        )

        investigation_json = json.dumps(
            investigation,
            indent=2,
            ensure_ascii=False
        )

        prompt = f"""
You are a cybersecurity SOC analyst assisting with a phishing
email investigation.

Analyze ONLY the structured evidence supplied below.

IMPORTANT RULES:

1. Do not invent URLs, domains, hashes, email addresses,
   VirusTotal results, or other indicators.
2. Do not invent MITRE ATT&CK techniques.
3. Do not claim an indicator is malicious unless the evidence
   supports that conclusion.
4. Zero VirusTotal detections do NOT prove that an indicator
   is safe.
5. Clearly distinguish observed evidence from interpretation.
6. Mention uncertainty when evidence is incomplete.
7. The risk score is a prioritization score, NOT a probability.
8. Do not recommend opening suspicious URLs or executing
   suspicious attachments.
9. Produce a professional SOC analyst report.

Return a JSON object containing:

{{
    "verdict": "Benign | Suspicious | Likely Phishing | Inconclusive",
    "confidence": "Low | Medium | High",
    "executive_summary": "short analyst summary",
    "key_findings": [
        "finding 1",
        "finding 2"
    ],
    "observed_iocs": [
        "IOC 1",
        "IOC 2"
    ],
    "mitre_attack": [
        "technique information"
    ],
    "recommended_actions": [
        "action 1",
        "action 2"
    ],
    "analyst_notes": "additional observations and limitations"
}}

STRUCTURED INVESTIGATION DATA:

{investigation_json}
"""

        response = client.responses.create(
            model="gpt-5.6-luna",
            input=prompt
        )

        content = response.output_text

        report = json.loads(content)

        return {
            "status": "success",
            "report": report
        }

    except Exception as error:

        return {
            "status": "error",
            "message": str(error)
        }