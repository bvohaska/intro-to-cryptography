# coding: utf-8

from fastapi.testclient import TestClient


from openapi_server.models.error import Error  # noqa: F401
from openapi_server.models.oracle_request import OracleRequest  # noqa: F401
from openapi_server.models.oracle_response import OracleResponse  # noqa: F401


def test_oracle_post(client: TestClient):
    """Test case for oracle_post

    The Encryption Oracle
    """
    oracle_request = openapi_server.OracleRequest()

    headers = {
    }
    response = client.request(
        "POST",
        "/oracle",
        headers=headers,
        json=oracle_request,
    )

    # uncomment below to assert the status code of the HTTP response
    #assert response.status_code == 200

