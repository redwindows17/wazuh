# app.py - vulnerable sample for CodeQL testing
from flask import Flask, request
import subprocess

app = Flask(__name__)

# ❌ Hardcoded secret (what we want CodeQL to find)
API_KEY = "DUMMY_SECRET_KEY_123456"

@app.route("/ping")
def ping():
    # ❌ Command injection (not needed for secret detection, but good to test)
    ip = request.args.get("ip", "127.0.0.1")
    return subprocess.getoutput(f"ping -c 1 {ip}")

if __name__ == "__main__":
    app.run(debug=True)
