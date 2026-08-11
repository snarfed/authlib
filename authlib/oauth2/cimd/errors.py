from ..base import OAuth2Error

__all__ = ["InvalidClientMetadataDocumentError"]


class InvalidClientMetadataDocumentError(OAuth2Error):
    error = "invalid_client_metadata_document"
    description = (
        "The client identifier URL does not return a valid client ID metadata document."
    )
    status_code = 400
