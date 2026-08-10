"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
The OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://tools.ietf.org/html/rfc9449
"""

from .authorization_server import DPoP
from .discovery import AuthorizationServerMetadata
from .errors import InvalidDPoPKeyBindingError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .grants import DPoPGrantExtension
from .models import AuthorizationCodeMixin
from .models import TokenMixin
from .nonce import DPoPNonceGenerator
from .nonce import HMACDPoPNonceGenerator
from .registration import ClientMetadataClaims
from .token import DPoPTokenGenerator
from .validator import DPoPProofValidator
from .validator import DPoPTokenValidator
from .validator import normalize_url

__all__ = [
    "AuthorizationCodeMixin",
    "AuthorizationServerMetadata",
    "ClientMetadataClaims",
    "DPoP",
    "DPoPGrantExtension",
    "DPoPNonceGenerator",
    "DPoPProofValidator",
    "DPoPTokenGenerator",
    "DPoPTokenValidator",
    "HMACDPoPNonceGenerator",
    "InvalidDPoPKeyBindingError",
    "InvalidDPoPProofError",
    "TokenMixin",
    "UseDPoPNonceError",
    "normalize_url",
]
