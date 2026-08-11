from joserfc.errors import InvalidClaimError
from joserfc.jwk import KeySet

from ..rfc7591 import ClientMetadataClaims as _ClientMetadataClaims

SYMMETRIC_AUTH_METHODS = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
]


class ClientMetadataClaims(_ClientMetadataClaims):
    """Client ID metadata document claims.

    This extends the :rfc:`RFC7591 <7591>` client metadata with the additional
    constraints a client ID metadata document must meet. The client identifier
    URL the document was fetched from is passed as the ``client_id`` param::

        claims = ClientMetadataClaims(document, {}, params={"client_id": client_id})
        claims.validate()
    """

    REGISTERED_CLAIMS = [*_ClientMetadataClaims.REGISTERED_CLAIMS, "client_id"]

    def validate(self, now=None, leeway=0):
        super().validate(now, leeway)
        self.validate_client_id()
        self.validate_client_secret()

    def validate_client_id(self):
        """The client ID metadata document MUST contain a ``client_id`` property
        whose value is identical to the client identifier URL the document was
        fetched from, compared using simple string comparison.
        """
        if self.get("client_id") != self.params.get("client_id"):
            raise InvalidClaimError("client_id")

    def validate_client_secret(self):
        """The client ID metadata document MUST NOT contain a ``client_secret``
        or ``client_secret_expires_at`` property, as the client identifier URL
        is public and cannot hold a secret.
        """
        for claim in ("client_secret", "client_secret_expires_at"):
            if claim in self:
                raise InvalidClaimError(claim)

    def validate_token_endpoint_auth_method(self):
        """The client cannot authenticate with a method based on a shared
        secret, since the document must not carry one. Unlike :rfc:`RFC7591
        <7591>`, the default is ``none`` rather than ``client_secret_basic``.
        """
        self.setdefault("token_endpoint_auth_method", "none")

        if self["token_endpoint_auth_method"] in SYMMETRIC_AUTH_METHODS:
            raise InvalidClaimError("token_endpoint_auth_method")

    def validate_redirect_uris(self):
        """Clients using redirect-based grants MUST register their redirection
        URIs in the document, and they are matched with simple string
        comparison.
        """
        if "redirect_uris" in self and not isinstance(self["redirect_uris"], list):
            raise InvalidClaimError("redirect_uris")

        super().validate_redirect_uris()

    def validate_jwks(self):
        """The document is public, so it MUST NOT contain private key material."""
        super().validate_jwks()

        if "jwks" in self and any(
            key.is_private for key in KeySet.import_key_set(self["jwks"]).keys
        ):
            raise InvalidClaimError("jwks")
