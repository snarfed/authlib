from authlib.oauth2.rfc6750.token import BearerTokenGenerator


class DPoPTokenGenerator(BearerTokenGenerator):
    """Token generator announcing ``DPoP`` as the token type, per `Section 5`_.

    .. code-block:: http

        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store

        {
            "access_token":"mF_9.B5f-4.1JqM",
            "token_type":"DPoP",
            "expires_in":3600,
            "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
        }

    Only register this when every access token the server issues is DPoP bound.
    The generator does not see the request, so it cannot tell a bound token from
    an unbound one; a server serving both kinds should keep the default
    :class:`~authlib.oauth2.rfc6750.BearerTokenGenerator`, whose ``Bearer`` type
    is what :rfc:`9449` expects for tokens that are not bound.

    Binding itself is not done here. ``save_token`` MUST persist
    ``request.payload.dpop_jkt`` alongside the token, and the token model MUST
    return it from ``get_dpop_jkt()``, or
    :class:`~authlib.oauth2.rfc9449.DPoPTokenValidator` cannot check the proof
    against the token.

    .. _`Section 5`: https://datatracker.ietf.org/doc/html/rfc9449#section-5
    """

    TOKEN_TYPE = "DPoP"
