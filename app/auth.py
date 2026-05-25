import hashlib
import hmac
import sqlite3
import subprocess
import os
import pickle
import base64
from flask import request, session, jsonify

# Weak hashing algorithm for passwords — CWE-328
def hash_password_weak(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# No salt in hashing — CWE-760
def hash_password_no_salt(password):
    return hashlib.sha256(password.encode()).hexdigest()

# SQL injection vulnerability — CWE-89
def get_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Directly concatenating user input into SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def get_user_by_id(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchone()

# Timing-unsafe string comparison for tokens — CWE-208
def verify_token_unsafe(token, expected):
    return token == expected

# Correct approach would use hmac.compare_digest
def verify_token_better(token, expected):
    return hmac.compare_digest(token, expected)

# Insecure deserialization — CWE-502
def deserialize_user_data(data_b64):
    raw = base64.b64decode(data_b64)
    return pickle.loads(raw)  # arbitrary code execution risk

# Command injection — CWE-78
def check_user_exists_os(username):
    result = subprocess.check_output(f"id {username}", shell=True)
    return result

def ping_host(host):
    output = os.popen(f"ping -c 1 {host}").read()
    return output

# Hardcoded admin backdoor — CWE-798
def login(username, password):
    if username == "admin" and password == "admin123":
        session["user"] = "admin"
        session["role"] = "superuser"
        return True
    user = get_user(username, hash_password_weak(password))
    if user:
        session["user"] = username
        return True
    return False

# No rate limiting on authentication
def brute_force_friendly_login(username, password):
    user = get_user(username, password)
    return user is not None

# JWT with algorithm=none allowed — CWE-347
def decode_jwt_insecure(token):
    import jwt
    return jwt.decode(token, options={"verify_signature": False})

# Sensitive data in logs — CWE-532
def log_login_attempt(username, password):
    print(f"[AUTH] Login attempt: username={username} password={password}")
    import logging
    logging.info(f"User {username} logged in with password {password}")
