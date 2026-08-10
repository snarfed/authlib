from authlib.oauth2.rfc6749 import InvalidGrantError
from authlib.oauth2.rfc6749.requests import OAuth2Request

from .validator import DPoPProofValidator


class DPoPGrantExtension:
    """DPoP extension for the Authorization Code and Refresh Token grants.

    It lets a client prove possession of a key pair by sending a DPoP proof with
    the token request, and binds the issued token to that key.

    DPoP stays optional per request: a token request without a DPoP header is
    left alone, so clients that do not use DPoP keep working. Once a code or
    refresh token has been bound to a key, though, a matching proof is required.

    ``AuthorizationCodeGrant.save_authorization_code`` MUST persist
    ``request.payload.dpop_jkt`` so that the binding survives to the token
    request, and ``save_token`` MUST persist ``request.payload.dpop_jkt`` so the
    resource server can check it later.
    """

    def __init__(self, proof_validator: DPoPProofValidator, get_client_metadata=None):
        self.proof_validator = proof_validator
        self.get_client_metadata = get_client_metadata

    def __call__(self, grant):
        grant.register_hook("after_validate_token_request", self.validate_dpop_jkt)

    def validate_dpop_jkt(self, grant, *args):
        request: OAuth2Request = grant.request

        credential = getattr(request, "authorization_code", None) or getattr(
            request, "refresh_token", None
        )
        existing_jkt = credential.get_dpop_jkt() if credential else None

        # A request with no proof is only refused when something already commits
        # this client to DPoP. Refusing every proofless request instead would
        # break clients that do not use DPoP the moment this extension is
        # registered, since one extension covers every grant on the server.
        if "DPoP" not in request.headers:
            if existing_jkt:
                raise InvalidGrantError(
                    "This grant is DPoP bound and requires a DPoP proof."
                )
            if self.client_requires_dpop(request.client):
                raise InvalidGrantError("Token requests for this client must use DPoP.")
            return

        proof_jkt = self.proof_validator.validate_proof(request)
        if existing_jkt and existing_jkt != proof_jkt:
            raise InvalidGrantError("DPoP proof does not match the expected jkt.")

        request.payload.dpop_jkt = proof_jkt

    def client_requires_dpop(self, client):
        if not self.get_client_metadata or not client:
            return False
        metadata = self.get_client_metadata(client)
        return bool(metadata and metadata.dpop_bound_access_tokens)
