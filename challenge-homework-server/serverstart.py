"""
   This script must be run from the cpa_server_fast_api/src directory. The FastAPI 
   libraries rely on relative imports that rely on running from that directory.
"""
import uvicorn
from uvicorn.config import LOGGING_CONFIG

deploy_port = 443

if __name__ == "__main__":
    LOGGING_CONFIG["formatters"]["default"]["fmt"] = "%(asctime)s [%(name)s] %(levelprefix)s %(message)s"
    uvicorn.run(
               "openapi_server.main:app",
               host="0.0.0.0",
               port=deploy_port,
               ssl_keyfile="/etc/letsencrypt/live/ineedrandom.com/privkey.pem",
               ssl_certfile="/etc/letsencrypt/live/ineedrandom.com/fullchain.pem",
            )
