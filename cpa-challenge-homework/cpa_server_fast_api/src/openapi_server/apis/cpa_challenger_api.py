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
from openapi_server.models.challenge_request import ChallengeRequest
from openapi_server.models.challenge_response import ChallengeResponse
from openapi_server.models.decision_request import DecisionRequest
from openapi_server.models.decision_response import DecisionResponse
from openapi_server.models.error import Error


from openapi_server.cpa_hw import server_key, admin_key, debug_mode, challenge_oracle, check_challenge, do_prf
from openapi_server.models.ciphertext import Ciphertext


state_dict = {}
victory_dict = {}


router = APIRouter()


@router.post(
    "/challenges",
    responses={
        200: {"model": ChallengeResponse, "description": "Challenge API response"},
        200: {"model": Error, "description": "unexpected error"},
    },
    tags=["CPA Challenger - HW2a"],
    summary="The CPA Challenger",
    response_model_by_alias=True,
)
async def challenges_post(
    challenge_request: ChallengeRequest = Body(None, description="Challenge API request"),
) -> ChallengeResponse:
    """Attempt to defeat the CPA challenger; submit 10 sets of 2 messages receive 10 challenges"""
    
    ciphertexts = []

    try:
        for item in challenge_request.messages:
            temp_ciphertext = challenge_oracle(
                server_key = server_key,
                state_dict = state_dict,
                challenge_m1= item[0] + challenge_request.password,
                challenge_m2= item[1] + challenge_request.password,
                output_hex=False,
                debug=debug_mode
            )
            ciphertexts.append(
                Ciphertext(
                    random_nonce = temp_ciphertext[0].hex(),
                    c1 = temp_ciphertext[1].hex(),
                    c2 = temp_ciphertext[2].hex()
                )
            )
    except Exception as e:
        print(f"Challenge oracle error {e}")

    if debug_mode:
        print(f"CPA Challenger Key (hex): {server_key.hex()}")
        for item in ciphertexts:
            print(item)

    return ChallengeResponse(ciphertexts=ciphertexts)


@router.post(
    "/decision",
    responses={
        200: {"model": DecisionResponse, "description": "Decision Response"},
        200: {"model": Error, "description": "unexpected error"},
    },
    tags=["CPA Challenger - HW2a"],
    summary="Make a decision about challenges",
    response_model_by_alias=True,
)
async def decision_post(
    decision_request: DecisionRequest = Body(None, description="Description of a decision request"),
) -> DecisionResponse:
    """Convince the CPA challenger that you can distinguish between valid ciphertexts and random 
        strings. You must submit 10 challenges from the challenges API and submit if they are 
        ciphertexts or random strings.
    """
    
    if debug_mode:
        print(f"DecisionRequest Password: {decision_request.password}")

    #TODO: make this an admin API or security backed feature b/c this isn't great
    if decision_request.password == admin_key:
        dict_od_successful_students = f"{victory_dict}"
        return DecisionResponse(success=dict_od_successful_students)

    temp_list = []
    for item in decision_request.decisions:
            temp_list.append( 
                [
                    (
                        bytes.fromhex(item.ciphertext.random_nonce), 
                        bytes.fromhex(item.ciphertext.c1), 
                        bytes.fromhex(item.ciphertext.c2)
                    ), 
                    item.decision
                ]
            )

    passed = check_challenge(
        state_dict=state_dict,
        decision_list=temp_list,
        debug=debug_mode
    )
    
    if not passed:
        return DecisionResponse(success="You did not pass all challenges")

    victory_dict[decision_request.password] = True

    i_won_proof = do_prf(bytes.fromhex(admin_key),bytes.fromhex(decision_request.password))

    return DecisionResponse(success="Congrats! You passed the CPA challenge", proof_of_completion=i_won_proof.hex())
