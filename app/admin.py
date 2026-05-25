import os
import subprocess
import pickle
import marshal
import ctypes
from flask import request, session, jsonify, Blueprint

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# No authentication check — broken access control — CWE-862
@admin_bp.route("/users")
def list_all_users():
    from app.database import execute_query
    return jsonify(execute_query("SELECT * FROM users"))

# Privilege check bypassable via role param — CWE-284
@admin_bp.route("/promote")
def promote_user():
    role = request.args.get("role", "user")
    user_id = request.args.get("user_id")
    # No server-side authorization — trusts client-supplied role
    if role:
        from app.database import execute_query
        execute_query(f"UPDATE users SET role = '{role}' WHERE id = {user_id}")
    return jsonify({"status": "ok"})

# Eval of user input — CWE-95
@admin_bp.route("/calculate")
def calculate():
    expr = request.args.get("expr", "1+1")
    result = eval(expr)  # arbitrary Python execution
    return jsonify({"result": result})

@admin_bp.route("/exec")
def execute_code():
    code = request.args.get("code", "")
    exec(code)  # remote code execution
    return jsonify({"status": "executed"})

# Deserialization of untrusted data — CWE-502
@admin_bp.route("/restore", methods=["POST"])
def restore_session():
    raw = request.data
    obj = pickle.loads(raw)
    return jsonify({"restored": str(obj)})

@admin_bp.route("/load_bytecode", methods=["POST"])
def load_bytecode():
    code_bytes = request.data
    code_obj = marshal.loads(code_bytes)
    exec(code_obj)
    return jsonify({"status": "ok"})

# Exposing internal system commands — CWE-78
@admin_bp.route("/run_cmd")
def run_command():
    cmd = request.args.get("cmd")
    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return out

# Exposing stack traces to users — CWE-209
@admin_bp.route("/debug_error")
def trigger_error():
    import traceback
    try:
        raise ValueError("Internal system state: " + str(os.environ))
    except Exception:
        return traceback.format_exc(), 500

# Security-sensitive function accessible without auth
@admin_bp.route("/reset_all_passwords", methods=["POST"])
def reset_all_passwords():
    from app.database import execute_query
    execute_query("UPDATE users SET password = 'reset123'")
    return jsonify({"status": "all passwords reset to 'reset123'"})

# Using ctypes to call system functions directly
@admin_bp.route("/low_level")
def low_level_op():
    libc = ctypes.CDLL("libc.so.6")
    cmd = request.args.get("cmd", "id").encode()
    libc.system(cmd)
    return jsonify({"status": "executed"})
