.. _specs/cimd:

Client ID Metadata Documents
============================

This section contains the generic implementation of `OAuth Client ID Metadata
Document <https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/>`_.

.. warning::

    This specification is an IETF draft, and it may still change in
    backwards-incompatible ways. The implementation follows draft 02.

This specification describes how a client can be identified by a ``https`` URL
instead of an identifier issued by the authorization server. Rather than
registering with :ref:`specs/rfc7591`, the client hosts a *client ID metadata
document* — a JSON document holding the same metadata — at its client
identifier URL. The authorization server downloads that document the first time
it sees the client.

Since the document is public, the client cannot hold a secret, and must
authenticate with an asymmetric method such as ``private_key_jwt``, publishing
its public keys with ``jwks`` or ``jwks_uri``.

Usage
-----

Authlib does not perform the HTTP request itself, so that you can use the HTTP
library, timeouts and cache of your choosing. Inherit
:class:`~authlib.oauth2.cimd.ClientIdMetadataDocument`, implement
:meth:`~authlib.oauth2.cimd.ClientIdMetadataDocument.fetch_client_id_metadata_document`,
and register the extension::

    import requests
    from authlib.oauth2 import cimd


    class ClientIdMetadataDocument(cimd.ClientIdMetadataDocument):
        def fetch_client_id_metadata_document(self, client_id):
            try:
                response = requests.get(client_id, allow_redirects=False, timeout=10)
                response.raise_for_status()
                return response.json()
            except (requests.RequestException, ValueError):
                return None


    authorization_server.register_extension(ClientIdMetadataDocument())

The extension wraps
:meth:`~authlib.oauth2.rfc6749.AuthorizationServer.query_client`, so clients
registered with your authorization server keep working unchanged and take
precedence over documents.

Your implementation is responsible for a few requirements Authlib cannot enforce
for you:

* HTTP redirects MUST NOT be followed, and any status code other than 200 is an
  error.
* No more than about 5 kilobytes should be read from the response.
* Documents MAY be cached, honoring the HTTP cache headers. Error responses and
  invalid documents MUST NOT be cached.
* Hostnames resolving to special-use IP addresses MUST NOT be fetched. Authlib
  rejects client identifier URLs that use a literal special-use address, but
  only your fetching code can check what a hostname resolves to.

Finally, advertise the support in your server metadata::

    metadata = rfc8414.AuthorizationServerMetadata(
        {..., "client_id_metadata_document_supported": True}
    )
    metadata.validate(metadata_classes=[cimd.AuthorizationServerMetadata])

API Reference
-------------

.. module:: authlib.oauth2.cimd

.. autoclass:: ClientIdMetadataDocument
    :member-order: bysource
    :members:

.. autoclass:: ClientIdMetadataDocumentClient
    :member-order: bysource
    :members:

.. autoclass:: ClientMetadataClaims
    :member-order: bysource
    :members:

.. autoclass:: AuthorizationServerMetadata
    :member-order: bysource
    :members:
