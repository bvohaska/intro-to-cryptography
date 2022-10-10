# coding: utf-8

from fastapi.testclient import TestClient


from openapi_server.models.decryption_oracle_request import DecryptionOracleRequest  # noqa: F401
from openapi_server.models.error import Error  # noqa: F401


def test_paddingoracle_post(client: TestClient):
    """Test case for paddingoracle_post

    The Padding Oracle - POST requests
    """
    decryption_oracle_request = openapi_server.DecryptionOracleRequest()

    headers = {
    }
    response = client.request(
        "POST",
        "/paddingoracle",
        headers=headers,
        json=decryption_oracle_request,
    )

    # uncomment below to assert the status code of the HTTP response
    #assert response.status_code == 200

