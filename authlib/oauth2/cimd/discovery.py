from authlib.oauth2.rfc8414.models import validate_boolean_value


class AuthorizationServerMetadata(dict):
    """Authorization Server Metadata extension for Client ID Metadata Documents.

    This class can be used with
    :meth:`~authlib.oauth2.rfc8414.AuthorizationServerMetadata.validate`
    to validate the client ID metadata document specific metadata::

        from authlib.oauth2 import cimd, rfc8414

        metadata = rfc8414.AuthorizationServerMetadata(data)
        metadata.validate(metadata_classes=[cimd.AuthorizationServerMetadata])
    """

    REGISTRY_KEYS = ["client_id_metadata_document_supported"]

    def validate_client_id_metadata_document_supported(self):
        """Indicates whether the authorization server supports fetching client metadata from client identifier URLs."""
        validate_boolean_value(self, "client_id_metadata_document_supported")
