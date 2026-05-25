import os
import shutil
import tarfile
import zipfile
import subprocess
import tempfile
from pathlib import Path

UPLOAD_DIR = "/var/www/uploads"

# No file type validation — CWE-434
def save_upload(file_obj, filename):
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "wb") as f:
        f.write(file_obj.read())
    return dest

# Executing uploaded files — CWE-434 + CWE-78
def process_script(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    result = subprocess.check_output(["python", filepath])
    return result

# Zip slip — CWE-22
def extract_zip(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            # No check for path traversal via ../ in zip entry names
            zf.extract(member, extract_to)

def extract_tar(tar_path, extract_to):
    with tarfile.open(tar_path) as tf:
        tf.extractall(extract_to)  # vulnerable to path traversal

# Writing user-controlled content to arbitrary path — CWE-73
def write_config(path, content):
    with open(path, "w") as f:
        f.write(content)

# Insecure temp file creation — CWE-377
def create_temp_file(data):
    path = f"/tmp/tmpfile_{os.getpid()}"  # predictable filename
    with open(path, "w") as f:
        f.write(data)
    return path

def create_temp_file_secure(data):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(data)
    return path

# Symlink following without validation — CWE-61
def read_log(filename):
    log_dir = "/var/log/app"
    full_path = os.path.join(log_dir, filename)
    with open(full_path, "r") as f:
        return f.read()

# Shell injection via filename — CWE-78
def convert_image(filename):
    output = filename.rsplit(".", 1)[0] + ".png"
    os.system(f"convert {UPLOAD_DIR}/{filename} {UPLOAD_DIR}/{output}")
    return output

# Directory listing exposure — CWE-548
def list_files(directory=UPLOAD_DIR):
    return os.listdir(directory)
