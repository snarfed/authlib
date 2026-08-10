"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DPoP errors, per `Section 7`_ and `Section 8`_.

.. _`Section 7`: https://datatracker.ietf.org/doc/html/rfc9449#section-7
.. _`Section 8`: https://datatracker.ietf.org/doc/html/rfc9449#section-8
"""

from authlib.oauth2.rfc6749.errors import ForbiddenError

__all__ = [
    "InvalidDPoPKeyBindingError",
    "InvalidDPoPProofError",
    "UseDPoPNonceError",
]


class OAuth2DPoPError(ForbiddenError):
    def __init__(
        self,
        description: str = None,
        algs: list[str] = None,
        for_resource: bool = False,
    ):
        self.for_resource = for_resource
        self.algs = " ".join(algs or [])
        #: at the token endpoint these are OAuth error responses (400), at a
        #: protected resource they are WWW-Authenticate challenges (401)
        status_code = 401 if for_resource else 400
        super().__init__(description, auth_type="DPoP", status_code=status_code)

    def get_body(self):
        if self.for_resource:
            return []
        return super().get_body()

    def get_extras(self):
        extras = super().get_extras()
        if self.algs:
            extras.append(f'algs="{self.algs}"')
        return extras


class InvalidDPoPProofError(OAuth2DPoPError):
    error = "invalid_dpop_proof"


class UseDPoPNonceError(OAuth2DPoPError):
    error = "use_dpop_nonce"

    def __init__(
        self, dpop_nonce, description=None, algs: list[str] = None, for_resource=False
    ):
        if not description:
            server_type = "Resource" if for_resource else "Authorization"
            description = f"{server_type} server requires nonce in DPoP proof"
        super().__init__(description=description, algs=algs, for_resource=for_resource)
        self.dpop_nonce = dpop_nonce

    def get_headers(self):
        headers = super().get_headers()
        headers.append(("DPoP-Nonce", self.dpop_nonce))
        return headers


class InvalidDPoPKeyBindingError(OAuth2DPoPError):
    error = "invalid_token"
    description = "Invalid DPoP key binding"

    def __init__(self, algs: list[str] = None):
        super().__init__(algs=algs, for_resource=True)
