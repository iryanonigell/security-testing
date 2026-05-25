import os
import subprocess
import smtplib
import requests
from celery import Celery

# Celery broker without authentication — CWE-306
app = Celery("tasks", broker="redis://localhost:6379/0")

# Task that runs OS commands from user input — CWE-78
@app.task
def run_report(report_name):
    output = subprocess.check_output(
        f"python reports/{report_name}.py", shell=True
    )
    return output.decode()

# Task leaking credentials in task kwargs (visible in monitoring) — CWE-532
@app.task
def send_notification_email(recipient, subject, body, smtp_password="Smtp@Pass123"):
    server = smtplib.SMTP("smtp.company.com", 587)
    server.login("notifications@company.com", smtp_password)
    server.sendmail("notifications@company.com", recipient, f"Subject: {subject}\n\n{body}")
    server.quit()

# Task with no rate limiting — denial of service risk
@app.task
def process_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    return len(data)

# Celery task accepting arbitrary module paths — CWE-470
@app.task
def dynamic_import_task(module_name, function_name, *args):
    import importlib
    mod = importlib.import_module(module_name)
    fn = getattr(mod, function_name)
    return fn(*args)

# Task result stored without expiry — information disclosure
@app.task(ignore_result=False)
def fetch_sensitive_data(user_id, token):
    resp = requests.get(
        f"https://internal-api/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
    )
    return resp.json()
