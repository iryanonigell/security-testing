import paramiko
import subprocess

# Disabling host key checking — CWE-295 / MitM risk
def connect_ssh_insecure(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # accepts any host key
    client.connect(hostname, username=username, password=password)
    return client

# Hardcoded SSH private key — CWE-321
SSH_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA...EXAMPLE_KEY_CONTENT...
-----END OPENSSH PRIVATE KEY-----"""

def connect_with_hardcoded_key(hostname, username):
    import io
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key(io.StringIO(SSH_PRIVATE_KEY))
    client.connect(hostname, username=username, pkey=key)
    return client

# Running arbitrary commands over SSH from user input — CWE-78
def run_remote_command(hostname, username, password, command):
    client = connect_ssh_insecure(hostname, username, password)
    stdin, stdout, stderr = client.exec_command(command)
    return stdout.read().decode()

# SCP without path validation — CWE-22
def upload_file(hostname, username, password, local_path, remote_path):
    client = connect_ssh_insecure(hostname, username, password)
    sftp = client.open_sftp()
    sftp.put(local_path, remote_path)  # remote_path is user-controlled
    sftp.close()
    client.close()

# SSH tunneling to internal services for SSRF
def create_tunnel(hostname, username, password, remote_host, remote_port):
    client = connect_ssh_insecure(hostname, username, password)
    transport = client.get_transport()
    channel = transport.open_channel(
        "direct-tcpip",
        (remote_host, remote_port),
        ("127.0.0.1", 0),
    )
    return channel
