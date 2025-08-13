# File: main.py

import uvicorn
from server import app
from alpharequestmanager.config import cfg as config

if __name__ == "__main__":

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        reload=False,
        ssl_keyfile = "cert/key.pem",
        ssl_certfile = "cert/cert.pem"
    )
