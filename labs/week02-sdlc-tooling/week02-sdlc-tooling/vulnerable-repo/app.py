"""
Deliberately INSECURE sample for Week 2 scanning practice.
Do NOT copy these patterns into real code. Find them with SAST + secret scanning.
"""
import sqlite3, hashlib, subprocess, os
from flask import Flask, request
from argon2 import PasswordHasher

app = Flask(__name__)
ph = PasswordHasher()

# CWE-798: hardcoded credentials / secret  (Gitleaks should flag this)
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89: SQL injection (string formatting into query)
    q = "SELECT * FROM users WHERE name = ?"

    return str(con.execute(q, (name,)).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78: No shell=True; arguments are passed separately
    return subprocess.check_output(
        ["ping", "-c", "1", host],
        text=True
    )

def store_password(pw):
    # CWE-327: Use Argon2 instead of MD5
    return ph.hash(pw)

if __name__ == "__main__":
    # CWE-489: Disable Flask debug mode
    app.run(debug=False)
