"""Deliberately vulnerable app for a CI/CD security lab. Do NOT expose publicly."""
import sqlite3
import subprocess

import yaml
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# VULN 1: hardcoded secret (fake) -> Gitleaks
INTERNAL_API_KEY = "9f8b2c7e4a1d6f3b0c5e8a7d2b4f6c1e9a3d5b7f"

DB = "lab.db"


def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        con.executemany(
            "INSERT INTO users (name, email) VALUES (?, ?)",
            [("alice", "alice@lab.test"), ("bob", "bob@lab.test")],
        )
    con.commit()
    con.close()


@app.route("/")
def index():
    return "cicdsec lab: /user?name=  /ping?host=  /hello?name=  POST /config"


# VULN 2: SQL injection -> CodeQL / Semgrep
@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect(DB)
    rows = con.execute(f"SELECT id, name, email FROM users WHERE name = '{name}'").fetchall()
    con.close()
    return jsonify(rows)


# VULN 3: OS command injection -> CodeQL / Semgrep
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return f"<pre>{out.stdout}{out.stderr}</pre>"


# VULN 4: server-side template injection / reflected XSS -> SAST + ZAP
@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template_string(f"<h1>Hello {name}</h1>")


# VULN 5: unsafe deserialization -> CodeQL / Semgrep
@app.route("/config", methods=["POST"])
def config():
    data = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"loaded": str(data)})


@app.route("/admin")
def admin():
    if request.headers.get("X-Internal-Admin") == "true":
        return "admin panel"
    return "forbidden", 403


if __name__ == "__main__":
    init_db()
    # VULN 6: debug mode on, bound to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
