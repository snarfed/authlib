"""authlib.oauth2.rfc9449.nonce.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Server side DPoP nonce generation, per `Section 8`_.

.. _`Section 8`: https://datatracker.ietf.org/doc/html/rfc9449#section-8
"""

import hashlib
import hmac
import time
from base64 import urlsafe_b64encode
from typing import Protocol

from authlib.common.encoding import to_bytes


class DPoPNonceGenerator(Protocol):
    def next(self) -> str:
        """Return the nonce to hand out to clients right now."""
        ...

    def check(self, nonce: str) -> bool:
        """Return whether ``nonce`` is one this server issued recently."""
        ...


class HMACDPoPNonceGenerator(DPoPNonceGenerator):
    """Nonce generator deriving nonces from a secret and the current time window.

    Nonces are a keyed hash of the window counter rather than random values, so
    every worker sharing ``secret`` issues and accepts the same nonces without
    coordinating. ``secret`` MUST be shared by all workers of a deployment and
    kept private; anyone holding it can mint valid nonces.

    A nonce is accepted for the window it was issued in, the one before, and the
    one after, so it stays valid for roughly ``max_age`` seconds and tolerates
    modest clock skew between servers.
    """

    DEFAULT_MAX_AGE = 3 * 60

    def __init__(self, secret, max_age: int = DEFAULT_MAX_AGE):
        self.secret = to_bytes(secret)
        self.max_age = max_age
        self.interval = max_age / 3

    def next(self) -> str:
        return self._compute(self._counter())

    def check(self, nonce: str) -> bool:
        # The window before covers a nonce issued just before a rollover; the
        # window after covers a server whose clock runs slightly behind the one
        # that issued the nonce.
        counter = self._counter()
        return any(
            hmac.compare_digest(nonce, self._compute(counter + offset))
            for offset in (0, -1, 1)
        )

    def _counter(self) -> int:
        return int(time.time() / self.interval)

    def _compute(self, counter: int) -> str:
        digest = hmac.new(self.secret, to_bytes(str(counter)), hashlib.sha256).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode()
