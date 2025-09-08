from abc import ABC
from typing import Any
from typing import Optional

from joserfc import jwt
from joserfc.errors import DecodeError
from joserfc.errors import JoseError
from joserfc.errors import UnsupportedAlgorithmError
from joserfc.jws import JWSRegistry

from authlib._joserfc_helpers import import_any_key
from authlib.deprecate import deprecate

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import ClientMixin
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .errors import InvalidRequestObjectError
from .errors import InvalidRequestUriError
from .errors import RequestNotSupportedError
from .errors import RequestUriNotSupportedError


class RequestURIExtension:
    """Dispatch the ``request_uri`` authorization request parameter to the
    handlers that can resolve it.

    A ``request_uri`` may designate a request object hosted by the client, as
    defined in :rfc:`RFC9101 <9101>`, or a payload pushed by the client and
    kept by the authorization server, as defined in :rfc:`RFC9126 <9126>`.
    Handlers are tried in registration order, and the first one returning
    data resolves the request.
    """

    def __init__(self):
        self._handlers: list["RequestURIHandler"] = []

    def __call__(self, server: AuthorizationServer):
        server.register_hook("before_get_authorization_grant", self.handle_request_uri)

    def register_handler(self, handler: "RequestURIHandler"):
        if handler not in self._handlers:
            self._handlers.append(handler)

    def handle_request_uri(self, server: AuthorizationServer, request: OAuth2Request):
        if "request_uri" not in request.payload.data:
            return

        if not self._handlers:
            raise RequestUriNotSupportedError(state=request.payload.state)

        for handler in self._handlers:
            request_uri_data = handler.get_request_uri_data(request)
            if request_uri_data:
                handler.handle_request_uri_data(request_uri_data, server, request)
                return

        raise InvalidRequestUriError(state=request.payload.state)


class RequestURIHandler(ABC):
    """Base class for the extensions resolving a ``request_uri`` parameter."""

    REQUEST_URI_EXTENSION = RequestURIExtension()

    def __call__(self, server: AuthorizationServer):
        server.register_extension(self.REQUEST_URI_EXTENSION)

    def get_request_uri_data(self, request: OAuth2Request) -> Any:
        """Return the data designated by the ``request_uri`` parameter, or
        :data:`None` when this handler cannot resolve it.
        """
        ...

    def handle_request_uri_data(
        self, request_uri_data: Any, server: AuthorizationServer, request: OAuth2Request
    ):
        """Replace the request payload with the resolved ``request_uri`` data."""
        ...


class JWTAuthorizationRequest(RequestURIHandler):
    """Authorization server extension implementing the support
    for JWT secured authorization request, as defined in :rfc:`RFC9101 <9101>`.

    :param support_request: Whether to enable support for the ``request`` parameter.
    :param support_request_uri: Whether to enable support for the ``request_uri`` parameter.

    This extension is intended to be inherited and registered into the authorization server::

        class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
            def resolve_client_public_key(self, client: ClientMixin):
                return get_jwks_for_client(client)

            def get_request_object(self, request_uri: str):
                try:
                    return requests.get(request_uri).text
                except requests.Exception:
                    return None

            def get_server_metadata(self):
                return {
                    "issuer": ...,
                    "authorization_endpoint": ...,
                    "require_signed_request_object": ...,
                }

            def get_client_require_signed_request_object(self, client: ClientMixin):
                return client.require_signed_request_object


        authorization_server.register_extension(JWTAuthorizationRequest())
    """

    claims_validator = jwt.JWTClaimsRegistry(
        client_id={"essential": True},
    )

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        self.support_request = support_request
        self.support_request_uri = support_request_uri

    def __call__(self, authorization_server: AuthorizationServer):
        super().__call__(authorization_server)
        if self.support_request_uri:
            self.REQUEST_URI_EXTENSION.register_handler(self)
        authorization_server.register_hook(
            "before_get_authorization_grant", self.parse_authorization_request
        )

    def get_request_object_signing_algorithms(self, client):
        """Return the supported algorithms for verifying the ``request_object`` JWT signature.
        By default, this method will only return the recommended algorithms. If signed request
        object is not required, "none" algorithm will be included.

        Developers can override this method to customize the supported algorithms::

            def get_request_object_signing_algorithms(self, client):
                return ["RS256"]
        """
        metadata = self.get_server_metadata()
        algorithms = metadata.get("request_object_signing_alg_values_supported")
        if not algorithms:
            require_signed1 = self.get_client_require_signed_request_object(client)
            require_signed2 = metadata.get("require_signed_request_object", False)
            if require_signed1 or require_signed2:
                algorithms = JWSRegistry.recommended
            else:
                algorithms = [*JWSRegistry.recommended, "none"]
        return algorithms

    def parse_authorization_request(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ):
        """Handle the ``request`` parameter, and enforce the presence of a
        request object when it is required.

        The ``request_uri`` parameter is handled by
        :class:`RequestURIExtension` instead.
        """
        # The request object has already been resolved from a ``request_uri``.
        if request.source:
            return

        client = self._query_client(authorization_server, request)

        if "request_uri" in request.payload.data:
            if "request" in request.payload.data:
                raise InvalidRequestError(
                    "The 'request' and 'request_uri' parameters are mutually exclusive.",
                    state=request.payload.state,
                )
            return

        if not self._shoud_proceed_with_request_object(request, client):
            return

        raw_request_object = request.payload.data["request"]
        self._handle_raw_request_object(raw_request_object, client, request)

    def get_request_uri_data(self, request: OAuth2Request) -> Optional[str]:
        if "request" in request.payload.data:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters are mutually exclusive.",
                state=request.payload.state,
            )

        return self.get_request_object(request.payload.data["request_uri"])

    def handle_request_uri_data(
        self,
        request_uri_data: str,
        server: AuthorizationServer,
        request: OAuth2Request,
    ):
        client = self._query_client(server, request)
        self._handle_raw_request_object(request_uri_data, client, request)

    def _handle_raw_request_object(
        self, raw_request_object: str, client: ClientMixin, request: OAuth2Request
    ):
        request_object = self._decode_request_object(
            request, client, raw_request_object
        )
        request.payload = BasicOAuth2Payload(request_object.claims)
        request.source = "jwt_authorization_request"

    def _query_client(
        self, authorization_server: AuthorizationServer, request: OAuth2Request
    ) -> ClientMixin:
        client_id = request.payload.client_id
        if client_id is None:
            raise InvalidClientError(
                status_code=404,
                description="Missing 'client_id' parameter.",
            )

        client = authorization_server.query_client(client_id)
        if not client:
            raise InvalidClientError(
                status_code=404,
                description="The client does not exist on this server.",
            )

        return client

    def _shoud_proceed_with_request_object(
        self,
        request: OAuth2Request,
        client: ClientMixin,
    ) -> bool:
        if "request" in request.payload.data:
            if not self.support_request:
                raise RequestNotSupportedError(state=request.payload.state)
            return True

        # When the value of it [require_signed_request_object] as client metadata is true,
        # then the server MUST reject the authorization request
        # from the client that does not conform to this specification.
        if self.get_client_require_signed_request_object(client):
            raise InvalidRequestError(
                "Authorization requests for this client must use signed request objects.",
                state=request.payload.state,
            )

        # When the value of it [require_signed_request_object] as server metadata is true,
        # then the server MUST reject the authorization request
        # from any client that does not conform to this specification.
        metadata = self.get_server_metadata()
        if metadata and metadata.get("require_signed_request_object", False):
            raise InvalidRequestError(
                "Authorization requests for this server must use signed request objects.",
                state=request.payload.state,
            )

        return False

    def _decode_request_object(
        self, request, client: ClientMixin, raw_request_object: str
    ):
        jwks = self.resolve_client_public_key(client)
        key = import_any_key(jwks)
        algorithms = self.get_request_object_signing_algorithms(client)

        try:
            request_object = jwt.decode(raw_request_object, key, algorithms=algorithms)
            self.claims_validator.validate(request_object.claims)
        except UnsupportedAlgorithmError as error:
            raise InvalidRequestError(
                "Authorization requests must be signed with supported algorithms.",
                state=request.payload.state,
            ) from error
        except DecodeError as error:
            raise InvalidRequestObjectError(state=request.payload.state) from error
        except JoseError as error:
            raise InvalidRequestObjectError(
                description=error.description or InvalidRequestObjectError.description,
                state=request.payload.state,
            ) from error

        # The client ID values in the client_id request parameter and in
        # the Request Object client_id claim MUST be identical.
        if request_object.claims["client_id"] != request.payload.client_id:
            raise InvalidRequestError(
                "The 'client_id' claim from the request parameters "
                "and the request object claims don't match.",
                state=request.payload.state,
            )

        # The Request Object MAY be sent by value, as described in Section 5.1,
        # or by reference, as described in Section 5.2. request and
        # request_uri parameters MUST NOT be included in Request Objects.
        if "request" in request_object.claims or "request_uri" in request_object.claims:
            raise InvalidRequestError(
                "The 'request' and 'request_uri' parameters must not be included in the request object.",
                state=request.payload.state,
            )

        return request_object

    def get_request_object(self, request_uri: str):
        """Download the request object at ``request_uri``.

        This method must be implemented if the ``request_uri`` parameter is supported::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def get_request_object(self, request_uri: str):
                    try:
                        return requests.get(request_uri).text
                    except requests.Exception:
                        return None
        """
        raise NotImplementedError()

    def resolve_client_public_key(self, client: ClientMixin):
        """Resolve the client public key for verifying the JWT signature.
        A client may have many public keys, in this case, we can retrieve it
        via ``kid`` value in headers. Developers MUST implement this method::

            from joserfc import KeySet


            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def resolve_client_public_key(self, client):
                    if client.jwks_uri:
                        data = requests.get(client.jwks_uri).json()
                        return KeySet.import_key_set(data)

                    return KeySet.import_key_set(client.jwks)
        """
        raise NotImplementedError()

    def get_server_metadata(self) -> dict:
        """Return server metadata which includes supported grant types,
        response types and etc.

        When the ``require_signed_request_object`` claim is :data:`True`,
        all clients require that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

            class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
                def get_server_metadata(self):
                    return {
                        "issuer": ...,
                        "authorization_endpoint": ...,
                        "require_signed_request_object": ...,
                        "request_object_signing_alg_values_supported": ["RS256", ...],
                    }

        """
        return {}  # pragma: no cover

    def get_client_require_signed_request_object(self, client: ClientMixin) -> bool:
        """Return the 'require_signed_request_object' client metadata.

        When :data:`True`, the client requires that authorization requests
        use request objects, and an error will be returned when the authorization
        request payload is passed in the request body or query string::

           class JWTAuthorizationRequest(rfc9101.JWTAuthorizationRequest):
               def get_client_require_signed_request_object(self, client):
                   return client.require_signed_request_object

        If not implemented, the value is considered as :data:`False`.
        """
        return False  # pragma: no cover


class JWTAuthenticationRequest(JWTAuthorizationRequest):
    """Deprecated alias for :class:`JWTAuthorizationRequest`.

    :rfc:`RFC9101 <9101>` secures the *authorization* request, not the
    authentication request.
    """

    def __init__(self, support_request: bool = True, support_request_uri: bool = True):
        deprecate(
            "'JWTAuthenticationRequest' is deprecated in favor of 'JWTAuthorizationRequest'.",
            version="1.9",
        )
        super().__init__(support_request, support_request_uri)
