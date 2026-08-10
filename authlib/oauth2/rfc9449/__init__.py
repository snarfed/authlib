"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~

This module represents a direct implementation of
The OAuth 2.0 Demonstrating Proof of Possession (DPoP).

https://tools.ietf.org/html/rfc9449
"""

from .errors import InvalidDPoPKeyBindingError
from .errors import InvalidDPopProofError
from .errors import UseDPoPNonceError
from .grants import DPoPGrantExtension
from .nonce import DefaultDPoPNonceGenerator
from .nonce import DPoPNonceGenerator
from .token import DPoPTokenGenerator
from .validator import DPoPProofValidator
from .validator import DPoPTokenValidator
from .validator import normalize_url

__all__ = [
    "DPoPGrantExtension",
    "DPoPNonceGenerator",
    "DPoPProofValidator",
    "DPoPTokenGenerator",
    "DPoPTokenValidator",
    "DefaultDPoPNonceGenerator",
    "InvalidDPoPKeyBindingError",
    "InvalidDPopProofError",
    "UseDPoPNonceError",
    "normalize_url",
]
