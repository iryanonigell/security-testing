import json
import pickle
import marshal
import shelve
import yaml
import xmlrpc.client

# Pickle deserialization of untrusted input — CWE-502
def load_user_session(data: bytes):
    return pickle.loads(data)

def save_user_session(obj) -> bytes:
    return pickle.dumps(obj)

# shelve (backed by pickle) with user-controlled key — CWE-502
def get_cached_data(key: str):
    with shelve.open("cache.db") as db:
        return db[key]

# YAML load without Loader (executes arbitrary Python) — CWE-502
def parse_config(yaml_str: str):
    return yaml.load(yaml_str)

def parse_config_safe(yaml_str: str):
    return yaml.safe_load(yaml_str)

# JSON with eval fallback — CWE-95
def parse_json_unsafe(data: str):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return eval(data)  # fallback to eval if JSON fails

# Exposing internal object attributes — CWE-200
def serialize_user(user_obj) -> dict:
    return user_obj.__dict__  # may expose password hash, tokens, internal state

# XML-RPC without authentication — CWE-306
def call_internal_rpc(method, *args):
    proxy = xmlrpc.client.ServerProxy("http://internal-rpc:8000/")
    return getattr(proxy, method)(*args)

# Marshal of untrusted bytecode — CWE-502
def load_plugin(bytecode: bytes):
    code = marshal.loads(bytecode)
    namespace = {}
    exec(code, namespace)
    return namespace
