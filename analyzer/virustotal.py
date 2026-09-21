import os
import base64
import requests
from dotenv import load_dotenv


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

VT_URL = "https://www.virustotal.com/api/v3"


def check_url_reputation(url):
    """
    Check a URL's reputation using VirusTotal.
    """

    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured."
        }

    try:

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"{VT_URL}/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            attributes = data["data"]["attributes"]

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "status": "success",
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        elif response.status_code == 404:

            return {
                "status": "not_found",
                "url": url,
                "message": "URL not found in VirusTotal."
            }

        elif response.status_code == 401:

            return {
                "status": "error",
                "message": "VirusTotal API key is invalid."
            }

        elif response.status_code == 429:

            return {
                "status": "error",
                "message": "VirusTotal API rate limit reached."
            }

        else:

            return {
                "status": "error",
                "message": (
                    f"VirusTotal returned HTTP "
                    f"{response.status_code}."
                )
            }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": f"Network error: {error}"
        }


def check_file_hash_reputation(file_hash):
    """
    Check a file SHA-256 hash using VirusTotal.
    """

    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured."
        }

    try:

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"{VT_URL}/files/{file_hash}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            attributes = data["data"]["attributes"]

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "status": "success",
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "filename": attributes.get("meaningful_name")
            }

        elif response.status_code == 404:

            return {
                "status": "not_found",
                "hash": file_hash,
                "message": "File hash not found in VirusTotal."
            }

        elif response.status_code == 401:

            return {
                "status": "error",
                "message": "VirusTotal API key is invalid."
            }

        elif response.status_code == 429:

            return {
                "status": "error",
                "message": "VirusTotal API rate limit reached."
            }

        else:

            return {
                "status": "error",
                "message": (
                    f"VirusTotal returned HTTP "
                    f"{response.status_code}."
                )
            }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": f"Network error: {error}"
        }