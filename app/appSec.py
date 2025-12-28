"""
File Name   : app.py
Description : Secure Flask web application
Purpose     : Secure Coding Review (hardened implementation)
Platform    : Kali Linux
"""

from flask import Flask, request, abort
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
import config
import logging
import os

app = Flask(__name__)

# Secure configuration
app.secret_key = config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app)

# Logging enabled
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def get_connection():
    return sqlite3.connect(config.DATABASE)

@app.route("/login", methods=["POST"])
def login():
    # Input validation
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        abort(400, "Invalid input")

    connection = get_connection()
    cursor = connection.cursor()

    # Parameterized query prevents SQL Injection
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    result = cursor.fetchone()
    connection.close()

    if result and check_password_hash(result[0], password):
        logging.info("Successful login for user: %s", username)
        return "Login Successful"

    logging.warning("Failed login attempt for user: %s", username)
    return "Invalid Credentials", 401


@app.before_request
def enforce_https():
    # Enforce HTTPS
    if not request.is_secure and os.getenv("FLASK_ENV") == "production":
        abort(403)


@app.after_request
def add_security_headers(response):
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


# Debug disabled
if __name__ == "__main__":
    app.run(debug=False)
