from flask import Flask, request, jsonify
from ai_analyzer import analyze_email

app = Flask(__name__)


@app.route("/")
def home():
    return "Email Guard AI is running"


@app.route("/api/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    subject = data.get("subject", "")
    body = data.get("body", "")

    result = analyze_email(subject, body)

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)