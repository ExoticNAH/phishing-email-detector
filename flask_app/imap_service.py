import imaplib
import email
from email.header import decode_header
from bs4 import BeautifulSoup
import re


# ---------- DANGEROUS ATTACHMENT EXTENSIONS ----------
DANGEROUS_EXTENSIONS = [
    ".exe", ".js", ".bat", ".scr",
    ".ps1", ".vbs", ".cmd", ".msi"
]


# =====================================================
# ---------- CONNECT (SECURE VERSION)
# =====================================================
def _connect(email_account, app_password):

    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com", timeout=10)
        imap.login(email_account, app_password)
        imap.select("INBOX")
        return imap

    except imaplib.IMAP4.error:
        raise Exception("Invalid credentials")

    except Exception as e:
        raise Exception(f"IMAP connection failed: {str(e)}")


# =====================================================
# ---------- HEADER DECODER (SAFE)
# =====================================================
def _decode_header_value(value):

    if not value:
        return ""

    try:
        decoded, encoding = decode_header(value)[0]

        if isinstance(decoded, bytes):
            return decoded.decode(encoding or "utf-8", errors="ignore")

        return decoded

    except:
        return str(value)


# =====================================================
# ---------- CLEAN HTML (SAFE TEXT ONLY)
# =====================================================
def _clean_html(html_content):

    soup = BeautifulSoup(html_content, "html.parser")

    # ❌ Remove dangerous/unnecessary tags
    for tag in soup(["script", "style", "head", "meta", "link"]):
        tag.decompose()

    text = soup.get_text(separator="\n")

    # Remove empty lines
    lines = [line.strip() for line in text.splitlines() if line.strip()]

    return "\n".join(lines)


# =====================================================
# ---------- EXTRACT LINKS
# =====================================================
def _extract_links(text):

    return re.findall(r"https?://[^\s]+", text)


# =====================================================
# ---------- FETCH EMAIL LIST
# =====================================================
def fetch_emails(email_account, app_password, limit=10):

    imap = _connect(email_account, app_password)

    try:
        status, messages = imap.search(None, "ALL")

        if status != "OK":
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

        return emails[::-1]

    finally:
        imap.logout()


# =====================================================
# ---------- FETCH SINGLE EMAIL
# =====================================================
def fetch_email_by_id(email_account, app_password, email_id):

    imap = _connect(email_account, app_password)

    try:
        status, msg_data = imap.fetch(email_id.encode(), "(RFC822)")

        if status != "OK":
            raise Exception("Failed to fetch email")

        msg = email.message_from_bytes(msg_data[0][1])

        body = ""
        html_body = ""
        attachments = []
        dangerous_found = False

        if msg.is_multipart():

            for part in msg.walk():

                content_type = part.get_content_type()
                filename = part.get_filename()

                # ---------- TEXT ----------
                if content_type == "text/plain" and not filename:

                    payload = part.get_payload(decode=True)

                    if payload:
                        body = payload.decode(errors="ignore")

                # ---------- HTML ----------
                elif content_type == "text/html" and not filename:

                    payload = part.get_payload(decode=True)

                    if payload:
                        html_body = payload.decode(errors="ignore")

                # ---------- ATTACHMENTS ----------
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

        # ---------- CLEAN BODY ----------
        if html_body:
            body = _clean_html(html_body)

        # ---------- EXTRACT LINKS ----------
        links = _extract_links(body)

        subject = _decode_header_value(msg.get("Subject"))

        return {
            "from": msg.get("From"),
            "subject": subject,
            "body": body,
            "links": links,
            "attachments": attachments,
            "dangerous_attachment": dangerous_found
        }

    finally:
        imap.logout()