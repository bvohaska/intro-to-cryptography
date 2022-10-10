# coding: utf-8

from fastapi.testclient import TestClient


from openapi_server.models.error import Error  # noqa: F401


def test_root_get(client: TestClient):
    """Test case for root_get

    Default landing page
    """

    headers = {
    }
    response = client.request(
        "GET",
        "/",
        headers=headers,
    )

    # uncomment below to assert the status code of the HTTP response
    #assert response.status_code == 200

