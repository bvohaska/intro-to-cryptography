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
from openapi_server.models.decryption_oracle_request import DecryptionOracleRequest
from openapi_server.models.error import Error

from openapi_server import padding_oracle

router = APIRouter()


@router.post(
    "/paddingoracle",
    responses={
        200: {"model": str, "description": "Successful Decryption Oracle Response"},
        200: {"model": Error, "description": "unexpected error"},
    },
    tags=["Padding Oracle Challenge - HW2b"],
    summary="The Padding Oracle - POST requests",
    response_model_by_alias=True,
)
async def paddingoracle_post(
    decryption_oracle_request: DecryptionOracleRequest = Body(None, description="Description of a question to the decryption oracle"),
) -> str:
    """Ask the padding oracle to decrypt a ciphertext."""
    return padding_oracle.decrypt(
        hex_iv=decryption_oracle_request.iv,
        hex_ct=decryption_oracle_request.ciphertext)
