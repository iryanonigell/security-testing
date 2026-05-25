import os
from app.routes import app
from app.config import SECRET_KEY, DEBUG

# Running with debug=True exposes interactive debugger — CWE-11
if __name__ == "__main__":
    app.secret_key = SECRET_KEY
    app.run(
        host="0.0.0.0",    # binds to all interfaces
        port=5000,
        debug=DEBUG,        # interactive debugger in production
        use_reloader=True,
        threaded=True,
    )
