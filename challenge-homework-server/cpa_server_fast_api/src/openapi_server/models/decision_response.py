# coding: utf-8

from __future__ import annotations
from datetime import date, datetime  # noqa: F401

import re  # noqa: F401
from typing import Any, Dict, List, Optional  # noqa: F401

from pydantic import AnyUrl, BaseModel, EmailStr, Field, validator  # noqa: F401


class DecisionResponse(BaseModel):
    """NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).

    Do not edit the class manually.

    DecisionResponse - a model defined in OpenAPI

        success: The success of this DecisionResponse.
        proof_of_completion: The proof_of_completion of this DecisionResponse [Optional].
    """

    success: str = Field(alias="success")
    proof_of_completion: Optional[str] = Field(alias="proof_of_completion", default=None)

DecisionResponse.update_forward_refs()
