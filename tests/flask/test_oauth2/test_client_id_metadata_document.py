import pytest
from flask import json

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import cimd
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import CodeGrantMixin
from .models import save_authorization_code

authorize_url = "/oauth/authorize"
token_url = "/oauth/token"

client_id = "https://client.test/oauth-client-metadata.json"


@pytest.fixture
def document():
    return {
        "client_id": client_id,
        "client_name": "Client ID Metadata Document client",
        "redirect_uris": ["https://client.test/authorized"],
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "scope": "profile",
        "token_endpoint_auth_method": "none",
    }


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)
    return server


def register_cimd(server, document=None, metadata=None, **kwargs):
    class ClientIdMetadataDocument(cimd.ClientIdMetadataDocument):
        def fetch_client_id_metadata_document(self, client_id):
            return document

        def get_server_metadata(self):
            return metadata or {}

    server.register_extension(ClientIdMetadataDocument(**kwargs))


def authorize(test_client, **params):
    url = add_params_to_uri(
        authorize_url,
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://client.test/authorized",
            **params,
        },
    )
    return test_client.post(url, data={"user_id": "1"})


def test_authorization_code_flow(test_client, server, document):
    """A client identified by a URL is resolved by fetching its metadata document."""
    register_cimd(server, document)

    rv = authorize(test_client)
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert "code" in params

    rv = test_client.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
            "client_id": client_id,
            "redirect_uri": "https://client.test/authorized",
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_get_authorize(test_client, server, document):
    register_cimd(server, document)
    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": client_id}
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"


def test_registered_client_takes_precedence(test_client, server, client, document):
    """A client already known to the server is never looked up as a document."""
    register_cimd(server, document)

    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    assert rv.data == b"ok"


def test_unknown_client_id_is_not_a_url(test_client, server, document):
    """A client_id that is not a URL is not looked up as a document."""
    register_cimd(server, document)

    url = add_params_to_uri(
        authorize_url, {"response_type": "code", "client_id": "client-id"}
    )
    rv = test_client.get(url)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_fetch_failure(test_client, server):
    """Fetching errors abort the authorization request."""
    register_cimd(server, None)

    rv = test_client.get(
        add_params_to_uri(
            authorize_url, {"response_type": "code", "client_id": client_id}
        )
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata_document"


@pytest.mark.parametrize(
    "invalid_client_id",
    [
        pytest.param("http://client.test/metadata.json", id="http-scheme"),
        pytest.param("https://user@client.test/metadata.json", id="userinfo"),
        pytest.param("https://client.test", id="no-path"),
        pytest.param("https://client.test/", id="root-path"),
        pytest.param("https://client.test/./metadata.json", id="dot-segment"),
        pytest.param("https://client.test/foo/../metadata.json", id="dot-dot-segment"),
        pytest.param("https://client.test/metadata.json#f", id="fragment"),
        pytest.param("https://127.0.0.1/metadata.json", id="loopback"),
        pytest.param("https://[::1]/metadata.json", id="loopback-v6"),
        pytest.param("https://10.0.0.1/metadata.json", id="private-address"),
    ],
)
def test_invalid_client_id_url(test_client, server, document, invalid_client_id):
    """Client identifier URLs that do not meet the requirements are rejected."""
    register_cimd(server, document)

    rv = test_client.get(
        add_params_to_uri(
            authorize_url, {"response_type": "code", "client_id": invalid_client_id}
        )
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def loopback_authorize(test_client, server, document, loopback_client_id, **kwargs):
    document["client_id"] = loopback_client_id
    register_cimd(server, document, **kwargs)
    return test_client.get(
        add_params_to_uri(
            authorize_url,
            {"response_type": "code", "client_id": loopback_client_id},
        )
    )


def test_loopback_allowed_for_development(test_client, server, document):
    """Deployments on a loopback address may opt in to loopback client identifiers."""
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://127.0.0.1/metadata.json",
        allow_loopback=True,
        metadata={"issuer": "http://127.0.0.1:5000"},
    )
    assert rv.data == b"ok"


def test_loopback_allowed_for_localhost_server(test_client, server, document):
    """A server whose issuer is localhost shares the loopback interface."""
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://127.0.0.1/metadata.json",
        allow_loopback=True,
        metadata={"issuer": "http://localhost:5000"},
    )
    assert rv.data == b"ok"


def test_loopback_denied_for_public_server(test_client, server, document):
    """A server that is not itself on loopback must not apply the exception.

    Otherwise an attacker controlled client identifier could make a production
    server issue requests against its own loopback interface.
    """
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://127.0.0.1/metadata.json",
        allow_loopback=True,
        metadata={"issuer": "https://provider.test"},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_loopback_denied_without_server_metadata(test_client, server, document):
    """Without an issuer to check, the exception cannot be granted."""
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://127.0.0.1/metadata.json",
        allow_loopback=True,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_loopback_denied_for_other_interface(test_client, server, document):
    """The client identifier must resolve to the same loopback interface."""
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://[::1]/metadata.json",
        allow_loopback=True,
        metadata={"issuer": "http://127.0.0.1:5000"},
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_localhost_hostname_denied_by_default(test_client, server, document):
    """The 'localhost' hostname is loopback too, even though it is not an address."""
    rv = loopback_authorize(
        test_client, server, document, "https://localhost/metadata.json"
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_localhost_hostname_allowed_for_development(test_client, server, document):
    rv = loopback_authorize(
        test_client,
        server,
        document,
        "https://localhost/metadata.json",
        allow_loopback=True,
        metadata={"issuer": "http://localhost:5000"},
    )
    assert rv.data == b"ok"


@pytest.mark.parametrize(
    "update",
    [
        pytest.param({"client_id": None}, id="missing-client-id"),
        pytest.param({"client_id": "https://client.test/other.json"}, id="mismatch"),
        pytest.param({"client_secret": "secret"}, id="client-secret"),
        pytest.param({"client_secret_expires_at": 0}, id="client-secret-expires-at"),
        pytest.param(
            {"token_endpoint_auth_method": "client_secret_basic"},
            id="client-secret-basic",
        ),
        pytest.param(
            {"token_endpoint_auth_method": "client_secret_post"},
            id="client-secret-post",
        ),
        pytest.param(
            {"token_endpoint_auth_method": "client_secret_jwt"}, id="client-secret-jwt"
        ),
        pytest.param({"redirect_uris": "https://client.test/authorized"}, id="uris"),
    ],
)
def test_invalid_document(test_client, server, document, update):
    """Documents that do not meet the requirements are rejected."""
    for key, value in update.items():
        if value is None:
            del document[key]
        else:
            document[key] = value
    register_cimd(server, document)

    rv = test_client.get(
        add_params_to_uri(
            authorize_url, {"response_type": "code", "client_id": client_id}
        )
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata_document"


@pytest.mark.parametrize(
    "redirect_uri",
    [
        pytest.param("https://client.test/authorized/", id="trailing-slash"),
        pytest.param("https://client.test/authorized?a=b", id="extra-query"),
        pytest.param("https://client.test/other", id="other-path"),
    ],
)
def test_redirect_uri_exact_match(test_client, server, document, redirect_uri):
    """Redirect URIs are compared to the document with exact string comparison."""
    register_cimd(server, document)

    rv = authorize(test_client, redirect_uri=redirect_uri)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_public_jwks(test_client, server, document):
    """A document may publish the client public keys."""
    document["jwks"] = read_file_path("jwks_public.json")
    register_cimd(server, document)

    rv = test_client.get(
        add_params_to_uri(
            authorize_url, {"response_type": "code", "client_id": client_id}
        )
    )
    assert rv.data == b"ok"


def test_private_jwks(test_client, server, document):
    """A document is public, so it must not carry private key material."""
    document["jwks"] = read_file_path("jwks_private.json")
    register_cimd(server, document)

    rv = test_client.get(
        add_params_to_uri(
            authorize_url, {"response_type": "code", "client_id": client_id}
        )
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client_metadata_document"


def test_client_secret_never_matches(test_client, server, document):
    """A document client has no secret, so secret based authentication always fails."""
    register_cimd(server, document)
    client = cimd.ClientIdMetadataDocumentClient(document)

    assert client.check_client_secret("") is False
    assert client.check_client_secret("secret") is False
