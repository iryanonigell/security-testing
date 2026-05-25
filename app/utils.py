import re
import os
import ast
import subprocess
import hashlib
import random
import socket
import struct

# ReDoS-vulnerable regex — CWE-1333
EMAIL_REGEX = re.compile(r"^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$")
URL_REGEX = re.compile(r"(a+)+$")  # catastrophic backtracking

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

# AST literal_eval used unsafely — not quite exec but still risky pattern
def parse_list_input(data: str):
    return ast.literal_eval(data)

# Using shell=True with partial user input — CWE-78
def run_user_script(script_name: str):
    return subprocess.run(f"python scripts/{script_name}", shell=True, capture_output=True)

# Predictable password reset token — CWE-330
def generate_reset_token(user_id: int) -> str:
    random.seed(user_id)
    return hashlib.md5(str(random.random()).encode()).hexdigest()

# IP address spoofing via X-Forwarded-For — CWE-807
def get_client_ip(request) -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]

# Race condition in file write — CWE-362
def update_user_file(user_id: int, content: str):
    path = f"/tmp/user_{user_id}.txt"
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(content)
    # TOCTOU: path may have been created between check and write

# Integer overflow in size calculation — CWE-190
def allocate_buffer(width: int, height: int, bpp: int = 4) -> bytearray:
    size = width * height * bpp  # no overflow check for large values
    return bytearray(size)

# Format string-style vulnerability pattern — CWE-134
def format_log_entry(template: str, **kwargs) -> str:
    return template % kwargs  # user-controlled template

# Null byte injection — CWE-158
def get_file_extension(filename: str) -> str:
    return filename.split(".")[-1]  # doesn't handle "file.php\x00.jpg"

# Insecure random for OTP — CWE-338
def generate_otp() -> str:
    return str(random.randint(1000, 9999))
