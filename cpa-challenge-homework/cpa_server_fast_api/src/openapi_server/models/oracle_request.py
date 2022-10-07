# coding: utf-8

from __future__ import annotations
from datetime import date, datetime  # noqa: F401

import re  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401

from pydantic import AnyUrl, BaseModel, EmailStr, Field, validator  # noqa: F401


class OracleRequest(BaseModel):
    """NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).

    Do not edit the class manually.

    OracleRequest - a model defined in OpenAPI

        password: The password of this OracleRequest [Optional].
        oracle_message: The oracle_message of this OracleRequest.
    """

    password: Optional[str] = Field(alias="password", default=None)
    oracle_message: str = Field(alias="oracle_message")

    @validator("password")
    def password_min_length(cls, value):
        assert len(value) >= 32
        return value

    @validator("password")
    def password_max_length(cls, value):
        assert len(value) <= 32
        return value

    @validator("oracle_message")
    def oracle_message_min_length(cls, value):
        assert len(value) >= 64
        return value

    @validator("oracle_message")
    def oracle_message_max_length(cls, value):
        assert len(value) <= 64
        return value

OracleRequest.update_forward_refs()