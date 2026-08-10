import pytest
from flask import json

from authlib.oauth2 import rfc9126
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize"
par_url = "/oauth/par"

payloads = {}
server_metadata = {}


@pytest.fixture(autouse=True)
def par_server(app, server, client):
    payloads.clear()
    server_metadata.clear()

    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "none"]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)

    class PushedAuthorizationEndpoint(rfc9126.PushedAuthorizationEndpoint):
        def save_request_payload(self, payload, request_uri, expires_at):
            payloads[request_uri] = payload

    class PushedAuthorizationRequest(rfc9126.PushedAuthorizationRequest):
        def get_request_payload(self, request_uri):
            return payloads.get(request_uri)

        def get_server_metadata(self):
            return rfc9126.AuthorizationServerMetadata(server_metadata)

    server.register_endpoint(PushedAuthorizationEndpoint(server))
    server.register_extension(PushedAuthorizationRequest())

    @app.route("/oauth/par", methods=["POST"])
    def pushed_authorization():
        return server.create_endpoint_response(
            PushedAuthorizationEndpoint.ENDPOINT_NAME
        )

    return server


def test_pushed_authorization_request(test_client):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
            "state": "abc",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 201, rv.data
    resp = json.loads(rv.data)
    assert resp["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert resp["expires_in"] == 60

    rv = test_client.get(
        authorize_url,
        query_string={"client_id": "client-id", "request_uri": resp["request_uri"]},
    )
    assert rv.data == b"ok", rv.data


def test_request_uri_rejected_at_par_endpoint(test_client):
    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "request_uri": "urn:ietf:params:oauth:request_uri:whatever",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_par_endpoint_itself_when_par_is_required(test_client):
    """A required-PAR server must still accept requests at the PAR endpoint.

    The PAR endpoint validates the pushed request by running it through
    ``get_authorization_grant``, which fires the same hook that enforces the
    requirement. That request is the one *creating* a ``request_uri``, so it
    cannot have come from one itself.
    """
    server_metadata["require_pushed_authorization_requests"] = True

    rv = test_client.post(
        par_url,
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
            "state": "abc",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert rv.status_code == 201, rv.data

    rv = test_client.get(
        authorize_url,
        query_string={
            "client_id": "client-id",
            "request_uri": json.loads(rv.data)["request_uri"],
        },
    )
    assert rv.data == b"ok", rv.data


def test_authorization_request_without_par_when_par_is_required(test_client):
    server_metadata["require_pushed_authorization_requests"] = True

    rv = test_client.get(
        authorize_url,
        query_string={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
            "state": "abc",
        },
    )
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_unknown_request_uri(test_client):
    rv = test_client.get(
        authorize_url,
        query_string={
            "client_id": "client-id",
            "request_uri": "urn:ietf:params:oauth:request_uri:nope",
        },
    )
    assert json.loads(rv.data)["error"] == "invalid_request_uri"
