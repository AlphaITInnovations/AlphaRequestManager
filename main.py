# File: main.py
import sys

import uvicorn
import asyncio
import logging

from server import app



if __name__ == "__main__":
    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        reload=False,
        ssl_keyfile="cert/key.pem",
        ssl_certfile="cert/cert.pem"
    )
