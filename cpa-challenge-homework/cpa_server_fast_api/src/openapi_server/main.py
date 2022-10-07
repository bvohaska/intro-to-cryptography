# coding: utf-8

"""
    CPA Challenge Server

    Students as a CPA adversary will attempt to defeat the CPA challenger

    The version of the OpenAPI document: 1.0.0
    Contact: brian@vohaska.com
    Generated by: https://openapi-generator.tech
"""


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from openapi_server.apis.cpa_challenger_api import router as CPAChallengerApiRouter
from openapi_server.apis.encryption_oracle_api import router as EncryptionOracleApiRouter

app = FastAPI(
    title="CPA Challenge Server",
    description="Students as a CPA adversary will attempt to defeat the CPA challenger",
    version="1.0.0",
)

origins = ["*"]
#     "http://localhost",
#     "https://localhost",
#     "http://localhost:8080",
#     "http://127.0.0.1",
#     "http://127.0.0.1:8080",
#     "https://ineedrandom.com"
# ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(CPAChallengerApiRouter)
app.include_router(EncryptionOracleApiRouter)