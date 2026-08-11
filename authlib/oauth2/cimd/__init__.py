"""authlib.oauth2.cimd.
~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
OAuth Client ID Metadata Document.

https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
"""

from .authorization_server import ClientIdMetadataDocument
from .claims import ClientMetadataClaims
from .discovery import AuthorizationServerMetadata
from .errors import InvalidClientMetadataDocumentError
from .models import ClientIdMetadataDocumentClient

__all__ = [
    "AuthorizationServerMetadata",
    "ClientIdMetadataDocument",
    "ClientIdMetadataDocumentClient",
    "ClientMetadataClaims",
    "InvalidClientMetadataDocumentError",
]
