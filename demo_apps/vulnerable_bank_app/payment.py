import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Vulnerable: CORS wildcard — mirrors app.use(cors({ origin: "*" }))
CORS(app, origins="*")

PAYMENT_GATEWAY = "BANK_URL"

# Vulnerable: TLS disabled — mirrors rejectUnauthorized: false
def process_payment(payload):
    return requests.post(
        f"{PAYMENT_GATEWAY}/transfer",
        json=payload,
        verify=False
    )

@app.route("/pay", methods=["POST"])
def pay():
    try:
        payload = request.json
        result = process_payment(payload)
        return jsonify(result.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
