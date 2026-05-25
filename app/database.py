import sqlite3
import os
import logging
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "app.db")

# No connection pooling or timeout — resource exhaustion risk
def get_connection():
    return sqlite3.connect(DB_PATH)

# SQL injection via f-string — CWE-89
def find_user(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT id, username, email, password FROM users WHERE username = '{username}'")
    return cur.fetchone()

def find_users_by_role(role):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE role = '" + role + "'"
    cur.execute(query)
    return cur.fetchall()

def search_products(keyword, category):
    conn = get_connection()
    cur = conn.cursor()
    # Both parameters unsanitized
    cur.execute(
        "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
        " AND category = '" + category + "'"
    )
    return cur.fetchall()

# Returning full password hash to caller — CWE-200
def get_user_with_password(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchone()

# Logging sensitive query parameters — CWE-532
def execute_query(query, params=None):
    logging.debug(f"Executing query: {query} with params: {params}")
    conn = get_connection()
    cur = conn.cursor()
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)
    return cur.fetchall()

# No input validation on delete — CWE-89 + destructive
def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()

# Storing plaintext password — CWE-256
def create_user(username, email, password):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        (username, email, password),  # password stored as-is
    )
    conn.commit()

# Overly broad exception handling hiding errors — CWE-390
def safe_query(query):
    try:
        conn = get_connection()
        return conn.execute(query).fetchall()
    except:
        pass  # silently swallows all errors including security exceptions

# Connection string with credentials in code — CWE-798
PROD_DB = "postgresql://dbadmin:Passw0rd!@prod-db.internal:5432/maindb"
BACKUP_DB = "mysql://root:root@backup-server/backupdb"
