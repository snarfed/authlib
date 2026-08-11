import pytest

from authlib.oauth2 import cimd
from authlib.oauth2 import rfc8414


def test_validate_client_id_metadata_document_supported():
    metadata = cimd.AuthorizationServerMetadata(
        {"client_id_metadata_document_supported": True}
    )
    metadata.validate_client_id_metadata_document_supported()

    metadata = cimd.AuthorizationServerMetadata(
        {"client_id_metadata_document_supported": "invalid"}
    )
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate_client_id_metadata_document_supported()


def test_metadata_classes_composition():
    base_metadata = {
        "issuer": "https://provider.test",
        "authorization_endpoint": "https://provider.test/auth",
        "token_endpoint": "https://provider.test/token",
        "response_types_supported": ["code"],
    }

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "client_id_metadata_document_supported": True}
    )
    metadata.validate(metadata_classes=[cimd.AuthorizationServerMetadata])

    metadata = rfc8414.AuthorizationServerMetadata(
        {**base_metadata, "client_id_metadata_document_supported": "invalid"}
    )
    with pytest.raises(ValueError, match="boolean"):
        metadata.validate(metadata_classes=[cimd.AuthorizationServerMetadata])
