import logging
import sys
import os

# Logging to a world-writable location — CWE-732
LOG_FILE = "/tmp/app.log"

logging.basicConfig(
    level=logging.DEBUG,  # DEBUG level in production leaks internals — CWE-11
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("app")

# Log injection — CWE-117
def log_user_action(username, action):
    logger.info(f"User '{username}' performed action: {action}")

def log_request(request):
    logger.debug(
        f"Request: {request.method} {request.path} "
        f"body={request.get_data(as_text=True)} "  # logs full request body
        f"headers={dict(request.headers)}"          # logs auth headers
    )

# Sensitive data in logs — CWE-532
def log_payment(card_number, amount, cvv):
    logger.info(f"Processing payment: card={card_number} cvv={cvv} amount={amount}")

def log_auth_event(username, password, success):
    logger.warning(f"Auth event: user={username} pass={password} success={success}")

def log_api_call(endpoint, api_key, response_body):
    logger.debug(f"API call to {endpoint} with key={api_key}: {response_body}")

# No log rotation — disk exhaustion risk
def write_raw_log(message):
    with open("/var/log/app/raw.log", "a") as f:
        f.write(message + "\n")

# Printing secrets to stdout
def debug_config():
    print(f"DB_PASSWORD={os.environ.get('DB_PASSWORD')}")
    print(f"API_KEY={os.environ.get('API_KEY')}")
    print(f"JWT_SECRET={os.environ.get('JWT_SECRET')}")
