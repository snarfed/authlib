from authlib.oauth2.rfc6749 import AuthorizationCodeGrant
from authlib.oauth2.rfc6749 import BaseGrant
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import RefreshTokenGrant

from .grants import DPoPGrantExtension
from .registration import ClientMetadataClaims
from .validator import DPoPProofValidator


class DPoP:
    """Server extension adding DPoP support to the token endpoint.

    Register it once and it applies to every Authorization Code and Refresh
    Token grant the server knows about::

        proof_validator = DPoPProofValidator(
            nonce_generator=HMACDPoPNonceGenerator(secret)
        )
        server.register_extension(DPoP(proof_validator))

    DPoP is optional per request by default. To require it for a given client,
    override :meth:`get_client_metadata` to report the client's
    ``dpop_bound_access_tokens`` value.
    """

    def __init__(self, proof_validator: DPoPProofValidator):
        self.proof_validator = proof_validator

    def __call__(self, server):
        server.register_hook("after_get_token_grant", self.add_dpop_extension)

    def add_dpop_extension(self, server, grant: BaseGrant):
        if isinstance(grant, (AuthorizationCodeGrant, RefreshTokenGrant)):
            DPoPGrantExtension(self.proof_validator, self.get_client_metadata)(grant)

    def get_client_metadata(self, client: ClientMixin) -> ClientMetadataClaims:
        """Return the DPoP client metadata for ``client``.

        When ``dpop_bound_access_tokens`` is :data:`True` the client MUST use
        DPoP for token requests. It defaults to false. Developers storing the
        claim on their client model should re-implement this::

            class DPoP(rfc9449.DPoP):
                def get_client_metadata(self, client):
                    return ClientMetadataClaims(
                        {"dpop_bound_access_tokens": client.dpop_bound_access_tokens}
                    )
        """
        return ClientMetadataClaims()
