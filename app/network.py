import requests
import urllib.request
import socket
import ssl
import smtplib
from urllib.parse import urlparse

# SSRF — CWE-918
def fetch_url(url):
    response = requests.get(url)  # no validation of internal/private addresses
    return response.text

def fetch_user_avatar(avatar_url):
    # Attacker can pass internal network addresses: http://169.254.169.254/
    resp = requests.get(avatar_url, timeout=5)
    return resp.content

def load_webhook(webhook_url, payload):
    # No allowlist for webhook targets
    requests.post(webhook_url, json=payload)

# Disabling SSL certificate verification — CWE-295
def fetch_insecure(url):
    return requests.get(url, verify=False).text

def fetch_with_disabled_ssl(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(url, context=ctx) as resp:
        return resp.read()

# Cleartext transmission of sensitive data — CWE-319
def send_credentials_http(username, password):
    requests.post("http://api.example.com/login", data={
        "username": username,
        "password": password,
    })

# Email header injection — CWE-93
def send_email(to_address, subject, body):
    server = smtplib.SMTP("smtp.example.com", 25)  # no TLS
    message = f"To: {to_address}\nSubject: {subject}\n\n{body}"
    server.sendmail("noreply@example.com", to_address, message)
    server.quit()

# DNS rebinding / SSRF via redirect follow
def fetch_follow_redirects(url):
    return requests.get(url, allow_redirects=True, verify=False).text

# Binding to all interfaces unnecessarily — CWE-605
def start_debug_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 8888))  # exposes to all network interfaces
    s.listen(5)
    return s

# HTTP instead of HTTPS for sensitive endpoints
API_ENDPOINT = "http://payments.internal/charge"  # should be https

def charge_card(card_token, amount):
    return requests.post(API_ENDPOINT, json={
        "token": card_token,
        "amount": amount,
    })
