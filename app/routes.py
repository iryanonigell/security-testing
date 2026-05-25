import os
import subprocess
import xml.etree.ElementTree as ET
import yaml
import sqlite3
from flask import Flask, request, render_template_string, jsonify, redirect, send_file

app = Flask(__name__)

# XSS via render_template_string with user input — CWE-79
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)

# Server-Side Template Injection — CWE-94
@app.route("/render")
def render_user_template():
    template = request.args.get("template", "Hello")
    return render_template_string(template)

# Path traversal — CWE-22
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    base_dir = "/var/www/uploads"
    # No sanitization — allows ../../etc/passwd
    filepath = os.path.join(base_dir, filename)
    return send_file(filepath)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    with open(path, "r") as f:
        return f.read()

# OS command injection — CWE-78
@app.route("/ping")
def ping():
    host = request.args.get("host")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result

@app.route("/lookup")
def nslookup():
    domain = request.args.get("domain")
    out = os.system(f"nslookup {domain}")
    return str(out)

# SQL injection — CWE-89
@app.route("/search")
def search_users():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    rows = cur.fetchall()
    return jsonify(rows)

# Open redirect — CWE-601
@app.route("/redirect")
def open_redirect():
    url = request.args.get("next", "/")
    return redirect(url)

# XXE via XML parsing — CWE-611
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    data = request.data
    # xml.etree.ElementTree is NOT vulnerable to XXE by default in Python 3,
    # but lxml with resolve_entities=True is — simulating the pattern
    tree = ET.fromstring(data)
    return ET.tostring(tree)

# YAML deserialization (yaml.load without Loader) — CWE-502
@app.route("/parse_yaml", methods=["POST"])
def parse_yaml():
    data = request.data.decode()
    result = yaml.load(data)  # should use yaml.safe_load
    return jsonify(result)

# Insecure direct object reference — CWE-639
@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM invoices WHERE id = {invoice_id}")
    return jsonify(cur.fetchone())

# Exposed debug endpoint
@app.route("/debug/env")
def debug_env():
    return jsonify(dict(os.environ))

@app.route("/debug/config")
def debug_config():
    from app.config import DATABASE_URL, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
    return jsonify({
        "db": DATABASE_URL,
        "aws_key": AWS_ACCESS_KEY_ID,
        "aws_secret": AWS_SECRET_ACCESS_KEY,
    })

# No CSRF protection on state-changing POST
@app.route("/transfer", methods=["POST"])
def transfer_funds():
    amount = request.form.get("amount")
    to_account = request.form.get("to")
    # No CSRF token checked
    return jsonify({"status": "transferred", "amount": amount, "to": to_account})

# Mass assignment / parameter pollution — CWE-915
@app.route("/update_profile", methods=["POST"])
def update_profile():
    user_data = request.json  # directly trusts all fields, including "role", "is_admin"
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    for key, val in user_data.items():
        cur.execute(f"UPDATE users SET {key} = '{val}' WHERE id = {user_data.get('id')}")
    conn.commit()
    return jsonify({"status": "updated"})
