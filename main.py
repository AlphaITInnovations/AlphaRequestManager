# File: main.py

import uvicorn
from server import app  # import der FastAPI‐Instanz aus server.py
from alpharequestmanager.database import update_ticket

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        reload=False,
        ssl_keyfile = "cert/key.pem",
        ssl_certfile = "cert/cert.pem"
    )
