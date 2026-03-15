import imaplib
import email
from email.header import decode_header
from cryptography.fernet import Fernet
import os
import json

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
KEY_PATH = os.path.join(os.path.dirname(__file__), "secret.key")

# ---------- DANGEROUS ATTACHMENT EXTENSIONS ----------
DANGEROUS_EXTENSIONS = [
    ".exe", ".js", ".bat", ".scr",
    ".ps1", ".vbs", ".cmd", ".msi"
]


# ---------- LOAD ENCRYPTION KEY ----------
def _load_key():

    if not os.path.exists(KEY_PATH):
        raise Exception("Encryption key not found. Run setup first.")

    with open(KEY_PATH, "rb") as key_file:
        return key_file.read()


# ---------- LOAD AND DECRYPT CREDENTIALS ----------
def _load_credentials():

    if not os.path.exists(CONFIG_PATH):
        raise Exception("Email credentials not configured.")

    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)

    email_account = config.get("email")
    encrypted_password = config.get("password")

    key = _load_key()
    cipher = Fernet(key)

    try:
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        raise Exception("Failed to decrypt stored email password.")

    return email_account, decrypted_password


# ---------- CONNECT TO GMAIL ----------
def _connect():

    EMAIL, APP_PASSWORD = _load_credentials()

    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(EMAIL, APP_PASSWORD)
    imap.select("INBOX")

    return imap


# ---------- SAFE HEADER DECODER ----------
def _decode_header_value(value):

    if not value:
        return ""

    decoded, encoding = decode_header(value)[0]

    if isinstance(decoded, bytes):
        return decoded.decode(encoding or "utf-8", errors="ignore")

    return decoded


# ---------- FETCH EMAIL LIST ----------
def fetch_emails(limit=10):

    imap = _connect()

    status, messages = imap.search(None, "ALL")

    if status != "OK":
        imap.logout()
        return []

    mail_ids = messages[0].split()[-limit:]

    emails = []

    for mail_id in mail_ids:

        status, msg_data = imap.fetch(mail_id, "(RFC822)")

        if status != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])

        subject = _decode_header_value(msg.get("Subject"))
        sender = msg.get("From")

        emails.append({
            "id": mail_id.decode(),
            "from": sender,
            "subject": subject
        })

    imap.logout()

    return emails[::-1]


# ---------- FETCH SINGLE EMAIL ----------
def fetch_email_by_id(email_id):

    imap = _connect()

    status, msg_data = imap.fetch(email_id.encode(), "(RFC822)")

    if status != "OK":
        imap.logout()
        raise Exception("Failed to fetch email")

    msg = email.message_from_bytes(msg_data[0][1])

    body = ""
    attachments = []
    dangerous_found = False

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()
            filename = part.get_filename()

            # ---------- EMAIL BODY ----------
            if content_type == "text/plain" and not filename:

                payload = part.get_payload(decode=True)

                if payload:
                    body = payload.decode(errors="ignore")

            elif content_type == "text/html" and not body:

                payload = part.get_payload(decode=True)

                if payload:
                    body = payload.decode(errors="ignore")

            # ---------- ATTACHMENT DETECTION ----------
            if filename:

                decoded_name = _decode_header_value(filename)

                attachments.append(decoded_name)

                for ext in DANGEROUS_EXTENSIONS:

                    if decoded_name.lower().endswith(ext):
                        dangerous_found = True

    else:

        payload = msg.get_payload(decode=True)

        if payload:
            body = payload.decode(errors="ignore")

    subject = _decode_header_value(msg.get("Subject"))

    imap.logout()

    return {
        "from": msg.get("From"),
        "subject": subject,
        "body": body,
        "attachments": attachments,
        "dangerous_attachment": dangerous_found
    }