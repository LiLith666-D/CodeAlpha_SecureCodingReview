"""
File Name   : app.py
Description : Intentionally vulnerable Flask web application
Purpose     : Secure Coding Review (demonstration of vulnerabilities)
Platform    : Kali Linux
WARNING     : Do NOT use in production
"""

from flask import Flask, request
import sqlite3
import subprocess
import pickle

app = Flask(__name__)

# 1. Hardcoded secret key
app.secret_key = "hardcoded_secret_key"

# 2. Debug mode enabled
DEBUG = True

@app.route("/login", methods=["POST"])
def login():
    # 3. No input validation
    username = request.form["username"]
    password = request.form["password"]

    # 4. Plaintext password usage
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # 5. SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    connection.close()

    if user:
        return "Login Successful"
    return "Invalid Credentials"


@app.route("/cmd")
def command_execution():
    # 6. Command Injection vulnerability
    cmd = request.args.get("cmd")
    output = subprocess.getoutput(cmd)
    return output


@app.route("/deserialize")
def insecure_deserialization():
    # 7. Insecure deserialization
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)


@app.route("/file")
def file_access():
    # 8. Path Traversal vulnerability
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()


@app.route("/xss")
def xss():
    # 9. Cross-Site Scripting (XSS)
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"


@app.route("/auth")
def broken_auth():
    # 10. Broken authentication and authorization
    role = request.args.get("role")
    if role == "admin":
        return "Admin Access Granted"
    return "User Access"


# 11. No HTTPS enforcement
# 12. No logging or monitoring
# 13. No rate limiting
# 14. No CSRF protection
# 15. No security headers

app.run(debug=DEBUG)
