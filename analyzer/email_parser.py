from email import policy
from email.parser import BytesParser


def parse_email(file_bytes):
    """
    Parse an .eml file and extract basic email information.
    """

    message = BytesParser(policy=policy.default).parsebytes(file_bytes)

    headers = {
        "from": message.get("From"),
        "to": message.get("To"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "message_id": message.get("Message-ID"),
    }

    return {
        "headers": headers,
        "message": message
    }


def extract_body(message):
    """
    Extract plain-text and HTML content from the email.
    """

    text_body = ""
    html_body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    text_body += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    html_body += part.get_content()
                except Exception:
                    pass

    else:

        content_type = message.get_content_type()

        if content_type == "text/plain":
            text_body = message.get_content()

        elif content_type == "text/html":
            html_body = message.get_content()

    return text_body, html_body