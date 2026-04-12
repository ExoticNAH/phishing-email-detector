from flask import Flask, render_template, request, jsonify, redirect, session
from flask_wtf import CSRFProtect

# FIXED IMPORT PATHS FOR DEPLOYMENT
from flask_app.imap_service import fetch_emails, fetch_email_by_id
from flask_app.bert_predictor import predict_email

from openai import OpenAI
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import re
import os
import bleach
from datetime import timedelta


app = Flask(__name__)

# ---------- SECURITY CONFIG ----------
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "super-secret-key")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,   # IMPORTANT for HTTPS (Render)
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15)
)

# ---------- CSRF PROTECTION ----------
csrf = CSRFProtect(app)


# ---------- RATE LIMITER ----------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)


# ---------- OPENAI CLIENT ----------
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_KEY)


# ---------- XSS SANITIZATION ----------
def sanitize_email_html(html_content):

    script_detected = False

    if "<script" in html_content.lower():
        script_detected = True

    allowed_tags = [
        "p", "b", "i", "u", "strong",
        "em", "br", "ul", "ol", "li",
        "a"
    ]

    allowed_attrs = {
        "a": ["href", "title"]
    }

    clean_html = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )

    if script_detected:
        warning = """
        <div class="xss-warning">
        ⚠ Malicious script removed for security
        </div>
        """
        clean_html = warning + clean_html

    return clean_html


# ---------- SIMPLE FEATURE EXTRACTION ----------
def extract_risks(text):

    risks = []

    urgency_words = [
        "urgent",
        "immediately",
        "verify",
        "suspended",
        "action required"
    ]

    if any(word in text.lower() for word in urgency_words):
        risks.append("Urgency language detected")

    if re.search(r"http[s]?://", text.lower()):
        risks.append("Suspicious link detected")

    if any(word in text.lower() for word in ["password", "login", "verify account"]):
        risks.append("Credential request detected")

    if re.search(r"<script.*?>", text.lower()) or "onerror=" in text.lower():
        risks.append("Possible XSS script detected")

    if "attachment" in text.lower():
        risks.append("Suspicious attachment mentioned")

    return risks


# ---------- CHATGPT SECURITY ANALYSIS ----------
def generate_ai_analysis(email_content, label, risks):

    prompt = f"""
You are a cybersecurity assistant helping a phishing detection system.

The system classified the email as: {label}

Detected Risk Indicators:
{risks}

Email Content:
{email_content}

Explain briefly why this email may be phishing or legitimate.
Then provide recommended actions for the user.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )

        return response.choices[0].message.content

    except Exception as e:
        print("ChatGPT error:", e)
        return "AI explanation unavailable."


# ---------- CHATGPT RISK EXPLANATION ----------
def explain_risk_with_ai(risk):

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": risk}],
            temperature=0.2
        )

        return response.choices[0].message.content

    except Exception as e:
        print("Risk explanation error:", e)
        return "Unable to generate explanation."


# ---------- WELCOME ----------
@app.route("/")
def welcome():
    return render_template("welcome.html")


# ---------- HOME ----------
@app.route("/home")
def home():

    if "email" not in session:
        return redirect("/setup")

    return render_template("home.html")


# ---------- SETUP (LOGIN EMAIL) ----------
@app.route("/setup", methods=["GET", "POST"])
def setup():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        # 🔥 PREVENT SESSION FIXATION
        session.clear()

        session["email"] = email
        session["password"] = password
        session.permanent = True

        return redirect("/home")

    return render_template("setup.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():

    session.clear()
    return redirect("/")


# ---------- INBOX ----------
@app.route("/inbox")
def inbox():

    if "email" not in session:
        return redirect("/setup")

    try:
        emails = fetch_emails(session["email"], session["password"], limit=15)

    except Exception as e:
        emails = []
        print("IMAP error:", e)

    return render_template("inbox.html", emails=emails)


# ---------- VIEW EMAIL ----------
@app.route("/email/<email_id>")
def view_email(email_id):

    if "email" not in session:
        return redirect("/setup")

    try:
        email_data = fetch_email_by_id(
            session["email"],
            session["password"],
            email_id
        )

        email_data["body"] = sanitize_email_html(email_data.get("body", ""))

    except Exception as e:

        print("Fetch email error:", e)

        email_data = {
            "from": "Error",
            "subject": "Unable to load email",
            "body": "Error retrieving email.",
            "attachments": [],
            "dangerous_attachment": False
        }

    return render_template("email_view.html", email=email_data)


# ---------- MANUAL ----------
@app.route("/manual")
def manual():
    return render_template("manual_scan.html")


# ---------- SCAN ----------
@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():

    content = request.form.get("content", "").strip()

    if not content:
        return jsonify({
            "label": "UNKNOWN",
            "confidence": 0,
            "risks": [],
            "analysis": "No content provided."
        })

    try:
        label, confidence = predict_email(content)

        risks = extract_risks(content)
        analysis = generate_ai_analysis(content, label, risks)

        return jsonify({
            "label": label.upper(),
            "confidence": round(confidence),
            "risks": risks,
            "analysis": analysis
        })

    except Exception as e:

        print("Scan error:", e)

        return jsonify({
            "label": "ERROR",
            "confidence": 0,
            "risks": [],
            "analysis": "System error occurred."
        })


# ---------- EXPLAIN RISK ----------
@app.route("/explain-risk", methods=["POST"])
@limiter.limit("30 per minute")
def explain_risk():

    risk = request.form.get("risk")

    if not risk:
        return jsonify({"explanation": "No risk provided."})

    explanation = explain_risk_with_ai(risk)

    return jsonify({"explanation": explanation})


# ---------- RUN ----------
if __name__ == "__main__":
    app.run()