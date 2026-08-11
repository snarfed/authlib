import ipaddress
import logging

from joserfc.errors import JoseError

from authlib.common.urls import is_valid_url
from authlib.common.urls import urlparse

from ..rfc6749 import AuthorizationServer
from .claims import ClientMetadataClaims
from .errors import InvalidClientMetadataDocumentError
from .models import ClientIdMetadataDocumentClient

log = logging.getLogger(__name__)


class ClientIdMetadataDocument:
    """Authorization server extension implementing support for client ID
    metadata documents, as defined in `OAuth Client ID Metadata Document
    <https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/>`_.

    Clients identified by a ``https`` URL are not registered with the
    authorization server. Instead, their metadata is fetched at their client
    identifier URL when they are first seen.

    :param allow_loopback: Whether to allow client identifier URLs pointing at a
        loopback address. This is only intended for development and testing
        deployments, where the authorization server itself runs on a loopback
        interface.

    This extension is intended to be inherited and registered into the
    authorization server::

        class ClientIdMetadataDocument(cimd.ClientIdMetadataDocument):
            def fetch_client_id_metadata_document(self, client_id):
                try:
                    response = requests.get(
                        client_id, allow_redirects=False, timeout=10
                    )
                    response.raise_for_status()
                    return response.json()
                except (requests.RequestException, ValueError):
                    return None


        authorization_server.register_extension(ClientIdMetadataDocument())

    Clients registered with the authorization server take precedence: the
    document is only fetched when :meth:`~authlib.oauth2.rfc6749.AuthorizationServer.query_client`
    does not know the client identifier.
    """

    def __init__(self, allow_loopback: bool = False):
        self.allow_loopback = allow_loopback

    def __call__(self, authorization_server: AuthorizationServer):
        query_client = authorization_server.query_client

        def query_client_or_metadata_document(client_id):
            if client := query_client(client_id):
                return client
            return self.resolve_client_id_metadata_document(client_id)

        authorization_server.query_client = query_client_or_metadata_document

    def resolve_client_id_metadata_document(self, client_id: str):
        """Return the client described by the document at ``client_id``, or
        :data:`None` when ``client_id`` is not a client identifier URL.
        """
        if not self.validate_client_id(client_id):
            return None

        document = self.fetch_client_id_metadata_document(client_id)
        if not isinstance(document, dict):
            raise InvalidClientMetadataDocumentError()

        claims = ClientMetadataClaims(document, {}, params={"client_id": client_id})
        try:
            claims.validate()
        except (JoseError, ValueError) as error:
            log.debug("Invalid client ID metadata document at %r: %s", client_id, error)
            raise InvalidClientMetadataDocumentError() from error

        return ClientIdMetadataDocumentClient(claims)

    def validate_client_id(self, client_id: str) -> bool:
        """Return whether ``client_id`` is a valid client identifier URL.

        A client identifier URL uses the ``https`` scheme, has no userinfo
        component, has a path component that is neither empty nor ``/`` and
        contains no ``.`` or ``..`` segments, and has no fragment.
        """
        if not client_id or not is_valid_url(client_id, fragments_allowed=False):
            return False

        parsed = urlparse.urlparse(client_id)
        if parsed.scheme != "https":
            return False

        segments = parsed.path.split("/")
        if parsed.path in ("", "/") or "." in segments or ".." in segments:
            return False

        return self.check_client_id_address(parsed.hostname)

    def check_client_id_address(self, hostname: str) -> bool:
        """Return whether a client identifier URL host is allowed.

        Client ID metadata documents must not be fetched at special-use IP
        addresses. Only literal addresses are checked here: since the document
        is downloaded by :meth:`fetch_client_id_metadata_document`, guarding
        against a hostname resolving to such an address is the responsibility of
        that method.
        """
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return True

        if address.is_loopback:
            return self.allow_loopback

        return address.is_global

    def fetch_client_id_metadata_document(self, client_id: str) -> dict | None:
        """Download the client ID metadata document at ``client_id``.

        Developers MUST implement this method. It should return the parsed JSON
        document, or :data:`None` if it cannot be fetched. HTTP redirects MUST
        NOT be followed, any status code other than 200 is an error, and no more
        than about 5 kilobytes should be read::

            class ClientIdMetadataDocument(cimd.ClientIdMetadataDocument):
                def fetch_client_id_metadata_document(self, client_id):
                    try:
                        response = requests.get(
                            client_id, allow_redirects=False, timeout=10
                        )
                        response.raise_for_status()
                        return response.json()
                    except (requests.RequestException, ValueError):
                        return None

        Documents may be cached, in which case HTTP cache headers should be
        honored. Error responses and invalid documents must never be cached.
        """
        raise NotImplementedError()
