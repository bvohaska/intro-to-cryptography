import uvicorn

deploy_port = 443

if __name__ == "__main__":
    uvicorn.run(
               "openapi_server.main:app",
               host="0.0.0.0",
               port=deploy_port,
               ssl_keyfile="/etc/letsencrypt/live/ineedrandom.com/privkey.pem",
               ssl_certfile="/etc/letsencrypt/live/ineedrandom.com/fullchain.pem",
            )

#uvicorn main:app 
# --ssl-certfile /etc/letsencrypt/live/ineedrandom.com/fullchain.pem 
# --ssl-keyfile /etc/letsencrypt/live/ineedrandom.com/privkey.pem 
# --host 0.0.0.0  --port 443

