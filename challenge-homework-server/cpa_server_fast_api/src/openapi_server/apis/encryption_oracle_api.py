# coding: utf-8

from typing import Dict, List  # noqa: F401

from fastapi import (  # noqa: F401
    APIRouter,
    Body,
    Cookie,
    Depends,
    Form,
    Header,
    Path,
    Query,
    Response,
    Security,
    status,
)

from openapi_server.models.extra_models import TokenModel  # noqa: F401
from openapi_server.models.error import Error
from openapi_server.models.oracle_request import OracleRequest
from openapi_server.models.oracle_response import OracleResponse


from openapi_server.cpa_hw import server_key, debug_mode, encryption_oracle
from openapi_server.models.ciphertext import Ciphertext


router = APIRouter()


@router.post(
    "/oracle",
    responses={
        200: {"model": OracleResponse, "description": "Successful Oracle Response"},
        200: {"model": Error, "description": "unexpected error"},
    },
    tags=["CPA Challenger - HW2a"],
    summary="The Encryption Oracle",
    response_model_by_alias=True,
)
async def oracle_post(
    oracle_request: OracleRequest = Body(None, description="Description of a question to the oracle"),
) -> OracleResponse:
    """Ask the encryption oracle to encrypt any 256-bit hex encoded string. Ask as many questions as you&#39;d like but please don&#39;t overload the server. You will have a unique password given to you by the professor"""
            
    r, c1, c2 = encryption_oracle(
        server_key, 
        oracle_request.oracle_message + oracle_request.password
    )
    ct = Ciphertext(
        random_nonce=r.hex(),
        c1=c1.hex(), 
        c2=c2.hex()
    )

    if debug_mode:
        print(f"Encryption Oracle Key (hex): {server_key.hex()}")

    return OracleResponse(ciphertext=ct)