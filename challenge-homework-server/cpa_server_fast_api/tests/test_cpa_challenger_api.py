# coding: utf-8

from fastapi.testclient import TestClient


from openapi_server.models.challenge_request import ChallengeRequest  # noqa: F401
from openapi_server.models.challenge_response import ChallengeResponse  # noqa: F401
from openapi_server.models.decision_request import DecisionRequest  # noqa: F401
from openapi_server.models.decision_response import DecisionResponse  # noqa: F401
from openapi_server.models.error import Error  # noqa: F401


def test_challenges_post(client: TestClient):
    """Test case for challenges_post

    The CPA Challenger
    """
    challenge_request = openapi_server.ChallengeRequest()

    headers = {
    }
    response = client.request(
        "POST",
        "/challenges",
        headers=headers,
        json=challenge_request,
    )

    # uncomment below to assert the status code of the HTTP response
    #assert response.status_code == 200


def test_decision_post(client: TestClient):
    """Test case for decision_post

    Make a decision about challenges
    """
    decision_request = openapi_server.DecisionRequest()

    headers = {
    }
    response = client.request(
        "POST",
        "/decision",
        headers=headers,
        json=decision_request,
    )

    # uncomment below to assert the status code of the HTTP response
    #assert response.status_code == 200

