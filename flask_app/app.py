from flask import Flask, render_template, request, jsonify, redirect, session
from flask_wtf import CSRFProtect

from flask_app.imap_service import fetch_emails, fetch_email_by_id
from flask_app.bert_predictor import predict_email

from openai import OpenAI
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import os
import bleach
import re
from urllib.parse import urlparse
from datetime import timedelta


app = Flask(__name__)

# ---------- SECURITY CONFIG ----------
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "super-secret-key")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    WTF_CSRF_SSL_STRICT=False
)

csrf = CSRFProtect(app)

@app.before_request
def make_session_permanent():
    session.permanent = True


# ---------- RATE LIMIT ----------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"]
)


# ---------- OPENAI ----------
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# =====================================================
# ---------- SANITIZATION ----------
# =====================================================
def sanitize_email_html(html_content):

    if not html_content:
        return ""

    script_detected = "<script" in html_content.lower()

    allowed_tags = ["p","b","i","u","strong","em","br","ul","ol","li","a"]
    allowed_attrs = {"a": ["href","title"]}

    clean_html = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )

    if script_detected:
        clean_html = """
        <div class="xss-warning">⚠ Malicious script removed</div>
        """ + clean_html

    return clean_html


# =====================================================
# ---------- RISK DETECTION ----------
# =====================================================
def extract_risks(text):

    risks = []
    t = text.lower()

    if any(w in t for w in ["urgent","immediately","verify","suspended"]):
        risks.append("Urgency language detected")

    if "http" in t:
        risks.append("Suspicious link detected")

    if any(w in t for w in ["password","login"]):
        risks.append("Credential request detected")

    if "<script" in t:
        risks.append("Possible XSS script")

    if "attachment" in t:
        risks.append("Suspicious attachment")

    return list(set(risks))


# =====================================================
# ---------- DOMAIN ----------
# =====================================================
def extract_domains(text):

    urls = re.findall(r'https?://[^\s]+', text)
    domains = set()

    for url in urls:
        try:
            domain = urlparse(url).hostname
            if domain:
                domains.add(domain)
        except:
            pass

    return list(domains)


def ai_domain_analysis(domain):

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{
                "role": "user",
                "content": f"""
You are a cybersecurity expert.

Analyze this domain: {domain}

Return:
Risk: Safe or Suspicious
Reason: short clear explanation
"""
            }],
            temperature=0.2,
            max_tokens=80
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"AI error: {str(e)}"


def analyze_domains(text):

    domains = extract_domains(text)
    results = []

    for d in domains:
        results.append({
            "domain": d,
            "analysis": ai_domain_analysis(d)
        })

    return results


# =====================================================
# ---------- AI ANALYSIS ----------
# =====================================================
def generate_ai_analysis(email_content, label, risks):

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{
                "role": "user",
                "content": f"""
You are a cybersecurity analyst.

Email content:
{email_content}

Classification: {label}
Detected risks: {risks}

Return STRICTLY:

Explanation:
Explain why this email is {label.lower()}.

Advice:
- action 1
- action 2
- action 3

Do NOT contradict the classification.
"""
            }],
            temperature=0.2,
            max_tokens=300
        )

        result = response.choices[0].message.content.strip()

        explanation = ""
        advice = ""

        if "Advice:" in result:
            parts = result.split("Advice:")
            explanation = parts[0].replace("Explanation:", "").strip()
            advice = parts[1].strip()
        else:
            explanation = result

        return explanation, advice

    except Exception as e:
        print("AI error:", e)
        return "AI analysis unavailable.", "No advice available."


# =====================================================
# ---------- ROUTES ----------
# =====================================================

@app.route("/")
def welcome():
    return render_template("welcome.html")


@app.route("/home")
def home():
    if "email" not in session:
        return redirect("/setup")
    return render_template("home.html")


# 🔥 FIXED SETUP ROUTE
@app.route("/setup", methods=["GET", "POST"])
def setup():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        # ---------- VALIDATION ----------
        if not email or not password:
            return render_template("setup.html", error="Please fill all fields")

        if "@" not in email:
            return render_template("setup.html", error="Invalid email format")

        try:
            # 🔐 VALIDATE IMAP LOGIN FIRST
            fetch_emails(email, password, limit=1)

            # ✅ ONLY CREATE SESSION IF VALID
            session.clear()
            session["email"] = email
            session["password"] = password

            return redirect("/home")

        except Exception as e:
            print("Login failed:", e)

            return render_template(
                "setup.html",
                error="Invalid email or app password"
            )

    return render_template("setup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/inbox")
def inbox():

    if "email" not in session:
        return redirect("/setup")

    try:
        emails = fetch_emails(session["email"], session["password"], limit=15)
    except Exception as e:
        print("IMAP error:", e)
        emails = []

    return render_template("inbox.html", emails=emails)


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
        print("Fetch error:", e)

        email_data = {
            "from": "Error",
            "subject": "Failed",
            "body": "Cannot load email",
            "attachments": [],
            "dangerous_attachment": False
        }

    return render_template("email_view.html", email=email_data)


@app.route("/manual")
def manual():
    return render_template("manual_scan.html")


# =====================================================
# ---------- SCAN ----------
# =====================================================
@csrf.exempt
@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():

    content = request.form.get("content","").strip()

    if not content:
        return jsonify({
            "label":"UNKNOWN",
            "confidence":0,
            "risks":[],
            "analysis":"No content",
            "advice":"",
            "domains":[]
        })

    try:
        label, confidence = predict_email(content)

        risks = extract_risks(content)

        analysis, advice = generate_ai_analysis(content, label, risks)

        domains = analyze_domains(content)

        return jsonify({
            "label": label.upper(),
            "confidence": round(float(confidence), 2),
            "risks": risks,
            "analysis": analysis,
            "advice": advice,
            "domains": domains
        })

    except Exception as e:
        print("Scan error:", e)

        return jsonify({
            "label":"ERROR",
            "confidence":0,
            "risks":[],
            "analysis":"Scan failed",
            "advice":"",
            "domains":[]
        })


# =====================================================
# ---------- RUN ----------
# =====================================================
if __name__ == "__main__":
    app.run()