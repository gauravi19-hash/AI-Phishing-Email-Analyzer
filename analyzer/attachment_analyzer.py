import hashlib


def extract_attachments(message):
    """
    Extract email attachments without executing them.
    """

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if not filename:
            continue

        payload = part.get_payload(decode=True)

        if payload is None:
            continue

        sha256_hash = hashlib.sha256(payload).hexdigest()

        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": sha256_hash
        })

    return attachments