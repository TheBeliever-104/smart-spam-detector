from flask import Flask, render_template, request
import os
import pickle
import re
from urllib.parse import urlparse
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# Production-friendly config
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Load model and vectorizer
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "rb.gy", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "bank", "secure", "account", "signin",
    "confirm", "password", "wallet", "reward", "claim", "free", "gift",
    "bonus", "payment", "alert"
]

def extract_links(text: str) -> list[str]:
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text)

def is_ip_address(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))

def analyze_single_link(link: str) -> dict:
    original_link = link

    if link.startswith("www."):
        link = "http://" + link

    parsed = urlparse(link)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = link.lower()

    flags = []
    score = 0

    if parsed.scheme == "http":
        flags.append("Uses insecure HTTP")
        score += 2

    if any(shortener in host for shortener in SHORTENERS):
        flags.append("Uses shortened URL")
        score += 3

    if is_ip_address(host.split(":")[0]):
        flags.append("Uses IP address instead of domain")
        score += 4

    if host.count(".") >= 3:
        flags.append("Too many subdomains")
        score += 2

    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if matched_keywords:
        flags.append("Contains suspicious keywords: " + ", ".join(matched_keywords))
        score += min(4, len(matched_keywords))

    if len(full_url) > 60:
        flags.append("Very long URL")
        score += 2

    if "@" in full_url:
        flags.append("Contains @ symbol")
        score += 4

    if host.count("-") >= 2:
        flags.append("Suspicious domain pattern")
        score += 2

    if any(x in path for x in ["verify", "login", "update", "secure", "account"]):
        flags.append("Suspicious path detected")
        score += 2

    if score >= 7:
        risk = "High"
        suspicious = True
    elif score >= 3:
        risk = "Medium"
        suspicious = True
    else:
        risk = "Low"
        suspicious = False

    return {
        "url": original_link,
        "score": score,
        "risk": risk,
        "suspicious": suspicious,
        "flags": flags
    }

def analyze_links(text: str) -> dict:
    links = extract_links(text)
    results = [analyze_single_link(link) for link in links]

    suspicious_links = [r for r in results if r["suspicious"]]

    overall_risk = "Low"
    if any(r["risk"] == "High" for r in results):
        overall_risk = "High"
    elif any(r["risk"] == "Medium" for r in results):
        overall_risk = "Medium"

    return {
        "total_links": len(links),
        "details": results,
        "suspicious_links": suspicious_links,
        "is_suspicious": len(suspicious_links) > 0,
        "overall_risk": overall_risk
    }

@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/detect")
def detect():
    return render_template("index.html")

@app.route("/health")
def health():
    return {"status": "ok"}, 200

@app.route("/predict", methods=["POST"])
def predict():
    message = request.form["message"]
    msg_type = request.form["type"]

    processed_message = message.lower()

    if msg_type == "email":
        processed_message += " email"
    elif msg_type == "link":
        processed_message += " link"

    link_data = analyze_links(message)

    if msg_type == "link":
        if link_data["total_links"] == 0:
            return render_template(
                "index.html",
                prediction="No Link Found",
                confidence=0,
                links=link_data,
                risk="Low"
            )

        if link_data["overall_risk"] == "High":
            result = "Spam"
            confidence = 90.0
            risk = "High"
        elif link_data["overall_risk"] == "Medium":
            result = "Spam"
            confidence = 78.0
            risk = "Medium"
        else:
            result = "Not Spam"
            confidence = 72.0
            risk = "Low"

        return render_template(
            "index.html",
            prediction=result,
            confidence=round(confidence, 2),
            links=link_data,
            risk=risk
        )

    vector = vectorizer.transform([processed_message])
    prediction = model.predict(vector)[0]
    prob = model.predict_proba(vector)[0]

    result = "Spam" if prediction == 1 else "Not Spam"
    confidence = max(prob) * 100

    risk = "Low"
    if prediction == 1 and link_data["overall_risk"] == "High":
        risk = "High"
    elif prediction == 1:
        risk = "High"
    elif link_data["overall_risk"] == "High":
        risk = "High"
    elif link_data["overall_risk"] == "Medium":
        risk = "Medium"

    return render_template(
        "index.html",
        prediction=result,
        confidence=round(confidence, 2),
        links=link_data,
        risk=risk
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)