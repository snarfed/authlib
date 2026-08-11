from ..rfc6749 import ClientMixin
from ..rfc6749 import list_to_scope
from ..rfc6749 import scope_to_list
from .claims import SYMMETRIC_AUTH_METHODS


class ClientIdMetadataDocumentClient(ClientMixin):
    """A client described by a client ID metadata document.

    Unlike registered clients, such a client only lives for the duration of the
    request, and all its metadata comes from the document fetched at its client
    identifier URL.
    """

    def __init__(self, client_metadata):
        self.client_metadata = client_metadata
        self.client_id = client_metadata["client_id"]

    @property
    def redirect_uris(self):
        return self.client_metadata.get("redirect_uris", [])

    @property
    def token_endpoint_auth_method(self):
        return self.client_metadata.get("token_endpoint_auth_method", "none")

    @property
    def grant_types(self):
        return self.client_metadata.get("grant_types", ["authorization_code"])

    @property
    def response_types(self):
        return self.client_metadata.get("response_types", ["code"])

    @property
    def scope(self):
        return self.client_metadata.get("scope", "")

    @property
    def jwks_uri(self):
        return self.client_metadata.get("jwks_uri")

    @property
    def jwks(self):
        return self.client_metadata.get("jwks", [])

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(scope_to_list(self.scope))
        return list_to_scope([s for s in scope_to_list(scope) if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        """The redirect URI is compared to the ones registered in the document
        using simple string comparison.
        """
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        """A client ID metadata document cannot carry a secret."""
        return False

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint != "token":
            return True
        return (
            method not in SYMMETRIC_AUTH_METHODS
            and method == self.token_endpoint_auth_method
        )

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types
