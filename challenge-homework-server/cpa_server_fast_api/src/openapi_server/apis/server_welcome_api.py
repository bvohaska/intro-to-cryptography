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


router = APIRouter()


@router.get(
    "/",
    responses={
        200: {"model": str, "description": "Welcomes you to the server"},
        200: {"model": Error, "description": "unexpected error"},
    },
    tags=["Server Welcome"],
    summary="Default landing page",
    response_model_by_alias=True,
)
async def root_get(
) -> str:
    """Ask the encryption oracle to encrypt any 256-bit hex encoded string. Ask as many questions as you&#39;d like but please don&#39;t overload the server. You will have a unique password given to you by the professor"""
    return "IV (hex): 26d1634eca6a0222fcff1f6d7bc87ddd \
     CIPHERTEXT (hex): d6c88784f890d6a24c5bf2f090c0aec7151c970066589f850df329ca127e031f638cbb004c563a6617c7b2fb09f17fc7"
