"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Validate DPoP proofs and DPoP bound access tokens.
"""

import hashlib
import hmac
import time
from base64 import urlsafe_b64encode
from threading import Lock
from typing import Protocol
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from joserfc import jws
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import import_key

from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6750 import BearerTokenValidator

from .errors import InvalidDPoPKeyBindingError
from .errors import InvalidDPoPProofError
from .errors import UseDPoPNonceError
from .nonce import DPoPNonceGenerator

#: ``alg`` values that are asymmetric digital signature algorithms. RFC 9449
#: forbids symmetric algorithms and ``none``, whatever the server allows.
ASYMMETRIC_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_url(url):
    """Normalize a URL for ``htu`` comparison.

    Drops the query and fragment per `Section 4.2`_, and applies the syntax and
    scheme based normalization of :rfc:`3986` sections 6.2.2 and 6.2.3 that
    `Section 4.3`_ recommends, so that equivalent URLs compare equal.

    .. _`Section 4.2`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.2
    .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if parts.port is not None and str(parts.port) != DEFAULT_PORTS.get(scheme):
        host = f"{host}:{parts.port}"
    return urlunsplit((scheme, host, parts.path or "/", "", ""))


def hash_access_token(access_token):
    """Return the ``ath`` value for an access token: base64url(sha256(token))."""
    digest = hashlib.sha256(access_token.encode()).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode()


class DPoPReplayCache(Protocol):
    def check_and_add(self, jti: str, expires_at: float) -> bool:
        """Record ``jti`` and return whether it had not been seen before.

        Returns :data:`False` if ``jti`` is a replay. Entries may be dropped
        once ``expires_at`` has passed.
        """
        ...


class MemoryDPoPReplayCache(DPoPReplayCache):
    """In-memory replay cache, suitable for a single-process deployment.

    Deployments running more than one worker MUST supply a shared
    implementation (Redis, memcached, ...) instead, otherwise a proof replayed
    against a different worker is not detected.
    """

    def __init__(self):
        self._seen = {}
        self._lock = Lock()

    def check_and_add(self, jti: str, expires_at: float) -> bool:
        now = time.time()
        with self._lock:
            for seen_jti, seen_expires in list(self._seen.items()):
                if seen_expires <= now:
                    del self._seen[seen_jti]
            if jti in self._seen:
                return False
            self._seen[jti] = expires_at
            return True


class DPoPProofValidator:
    """Validate that a DPoP proof is correctly formed for the current request.

    :param nonce_generator: issues and checks server provided nonces. When set,
        proofs without a valid ``nonce`` are rejected with
        :class:`UseDPoPNonceError`, which carries a fresh nonce for the client
        to retry with.
    :param algs: the ``alg`` values this server accepts. Only asymmetric
        algorithms are ever accepted, whatever is listed here.
    :param iat_leeway: how far, in seconds, ``iat`` may be from the current
        time. Ignored when a ``nonce_generator`` is configured, since the nonce
        already bounds the proof's age.
    :param replay_cache: records ``jti`` values to reject replayed proofs.

    .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
    """

    DEFAULT_SUPPORTED_ALGS = ["ES256"]
    DEFAULT_IAT_LEEWAY = 60

    def __init__(
        self,
        nonce_generator: DPoPNonceGenerator = None,
        algs: list[str] = None,
        iat_leeway: int = DEFAULT_IAT_LEEWAY,
        replay_cache: DPoPReplayCache = None,
    ):
        self.nonce_generator = nonce_generator
        self.algs = list(algs or self.DEFAULT_SUPPORTED_ALGS)
        self.iat_leeway = iat_leeway
        self.replay_cache = (
            replay_cache if replay_cache is not None else MemoryDPoPReplayCache()
        )

    def validate_proof(
        self,
        request: OAuth2Request,
        access_token: str = None,
        for_resource: bool = False,
    ) -> str:
        """Validate the DPoP proof on ``request`` per `Section 4.3`_.

        :param request: the current request
        :param access_token: the access token presented alongside the proof,
            when validating a protected resource request
        :param for_resource: whether this is a protected resource request,
            which changes the status code and error format of failures
        :return: the JWK thumbprint of the proof's public key, to compare
            against the binding recorded for the code, token, or grant
        :raise InvalidDPoPProofError: the proof is missing or malformed
        :raise UseDPoPNonceError: a nonce is required, missing, or stale

        .. _`Section 4.3`: https://datatracker.ietf.org/doc/html/rfc9449#section-4.3
        """
        proof = request.headers.get("DPoP")
        if not proof:
            raise InvalidDPoPProofError(
                "DPoP proof required", algs=self.algs, for_resource=for_resource
            )

        # There is not more than one DPoP HTTP request header field. A repeated
        # header is folded into one comma separated value by HTTP.
        if "," in proof:
            raise InvalidDPoPProofError(
                "DPoP header must contain a single proof",
                algs=self.algs,
                for_resource=for_resource,
            )

        # The header is checked, and the proof's key recovered from it, before
        # the signature is verified, so that a proof naming an unacceptable alg
        # is rejected without that algorithm ever being run.
        header = self.extract_header(proof, for_resource=for_resource)
        key = self.validate_header(header, for_resource=for_resource)

        # The JWT signature verifies with the public key contained in the jwk
        # JOSE Header Parameter.
        try:
            token = jwt.decode(proof, key, algorithms=[header["alg"]])
        except (JoseError, ValueError) as error:
            raise InvalidDPoPProofError(
                f"DPoP proof is invalid: {error}",
                algs=self.algs,
                for_resource=for_resource,
            ) from error

        self.validate_claims(
            token.claims,
            request,
            access_token=access_token,
            for_resource=for_resource,
        )
        return key.thumbprint()

    def extract_header(self, proof, for_resource: bool = False) -> dict:
        """Return the proof's JOSE header without verifying its signature."""
        try:
            return jws.extract_compact(proof.encode()).protected
        except (JoseError, ValueError, AttributeError) as error:
            raise InvalidDPoPProofError(
                "DPoP proof is not a well-formed JWT",
                algs=self.algs,
                for_resource=for_resource,
            ) from error

    def validate_header(self, header: dict, for_resource: bool = False):
        """Validate the JOSE header and return the key that must have signed it.

        Developers MAY re-implement this method to check additional headers.
        """
        # The typ JOSE Header Parameter has the value dpop+jwt.
        if header.get("typ") != "dpop+jwt":
            raise InvalidDPoPProofError(
                "DPoP 'typ' header must be 'dpop+jwt'",
                algs=self.algs,
                for_resource=for_resource,
            )

        # The alg JOSE Header Parameter indicates a registered asymmetric digital
        # signature algorithm, is not none, is supported by the application, and
        # is acceptable per local policy. ASYMMETRIC_ALGS is checked separately
        # from self.algs so that a server cannot configure its way into
        # accepting a symmetric alg, where the proof's own jwk would be the
        # verification key and anyone could forge a proof.
        alg = header.get("alg")
        if alg not in self.algs or alg not in ASYMMETRIC_ALGS:
            raise InvalidDPoPProofError(
                f"DPoP 'alg' header must be one of {self.algs}",
                algs=self.algs,
                for_resource=for_resource,
            )

        if "jwk" not in header:
            raise InvalidDPoPProofError(
                "DPoP 'jwk' header required",
                algs=self.algs,
                for_resource=for_resource,
            )

        try:
            key = import_key(header["jwk"])
        except (JoseError, ValueError, TypeError) as error:
            raise InvalidDPoPProofError(
                "DPoP 'jwk' header is not a valid key",
                algs=self.algs,
                for_resource=for_resource,
            ) from error

        # The jwk JOSE Header Parameter does not contain a private key.
        if key.is_private:
            raise InvalidDPoPProofError(
                "DPoP 'jwk' header must be a public key",
                algs=self.algs,
                for_resource=for_resource,
            )
        return key

    def validate_claims(
        self,
        claims: dict,
        request: OAuth2Request,
        access_token: str = None,
        for_resource: bool = False,
    ):
        """Validate the proof's claims against the current request."""

        def invalid(message):
            return InvalidDPoPProofError(
                message, algs=self.algs, for_resource=for_resource
            )

        # All required claims per Section 4.2 are contained in the JWT.
        for name in ("jti", "htm", "htu", "iat"):
            if name not in claims:
                raise invalid(f"DPoP proof missing '{name}' claim")

        # The htm claim matches the HTTP method of the current request.
        if claims["htm"] != request.method:
            raise invalid("DPoP 'htm' claim does not match the request method")

        # The htu claim matches the HTTP URI value for the HTTP request in which
        # the JWT was received, ignoring any query and fragment parts. Both
        # sides are normalized, which Section 4.3 recommends to reduce the
        # likelihood of false negatives.
        if normalize_url(claims["htu"]) != normalize_url(request.uri):
            raise invalid("DPoP 'htu' claim does not match the request URI")

        if not isinstance(claims["iat"], (int, float)):
            raise invalid("DPoP 'iat' claim must be a number")

        # The creation time of the JWT, as determined by either the iat claim or
        # a server managed timestamp via the nonce claim, is within an
        # acceptable window. A nonce is the stronger of the two, since it is
        # bound to a time window the server itself chose, so iat is only checked
        # when no nonce is in play.
        if not self.nonce_generator:
            age = time.time() - claims["iat"]
            if abs(age) > self.iat_leeway:
                raise invalid("DPoP 'iat' claim is outside the acceptable window")

        # When presented to a protected resource in conjunction with an access
        # token, the value of the ath claim equals the hash of that access token.
        if access_token is not None:
            if "ath" not in claims:
                raise invalid("DPoP proof missing 'ath' claim")
            if not isinstance(claims["ath"], str) or not hmac.compare_digest(
                claims["ath"], hash_access_token(access_token)
            ):
                raise invalid("DPoP 'ath' claim does not match the access token")

        # If the server provided a nonce value to the client, the nonce claim
        # matches the server-provided nonce value. Both failures carry a fresh
        # nonce, which is how the client learns what to retry with.
        if self.nonce_generator:
            if "nonce" not in claims:
                raise UseDPoPNonceError(
                    self.nonce_generator.next(), for_resource=for_resource
                )
            if not self.nonce_generator.check(claims["nonce"]):
                raise UseDPoPNonceError(
                    self.nonce_generator.next(),
                    description="DPoP 'nonce' claim is invalid or has expired",
                    for_resource=for_resource,
                )

        # Section 11.1: to prevent replay, servers should store the jti of each
        # received proof for as long as that proof would remain acceptable.
        # Checked last, so that a proof rejected for any other reason does not
        # burn its jti and turn a retry into a spurious replay error.
        expires_at = claims["iat"] + self.iat_leeway
        if not self.replay_cache.check_and_add(str(claims["jti"]), expires_at):
            raise invalid("DPoP proof 'jti' has already been used (replay)")


class DPoPTokenValidator(BearerTokenValidator):
    """Resource server validator for DPoP bound access tokens.

    Register alongside the proof validator used by the authorization server::

        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(
            DPoPTokenValidator(proof_validator=proof_validator)
        )

    The token model MUST implement ``get_dpop_jkt()``, returning the thumbprint
    recorded when the token was issued.
    """

    TOKEN_TYPE = "dpop"

    def __init__(
        self, proof_validator: DPoPProofValidator, realm=None, **extra_attributes
    ):
        super().__init__(realm, **extra_attributes)
        self.proof_validator = proof_validator

    def validate_token(self, token, scopes, request):
        super().validate_token(token, scopes, request)

        # The access token is needed to check the proof's ath claim. The scheme
        # has already been matched by the resource protector to route here, so
        # this only has to split it back off.
        authorization = request.headers.get("Authorization", "")
        parts = authorization.split(maxsplit=1)
        access_token = parts[1] if len(parts) == 2 else ""

        proof_jkt = self.proof_validator.validate_proof(
            request, access_token=access_token, for_resource=True
        )

        # Confirm that the public key to which the access token is bound matches
        # the public key from the DPoP proof. An unbound token reaching here was
        # issued without DPoP and must not be accepted on the strength of a
        # proof the client minted for a key of its own choosing.
        token_jkt = token.get_dpop_jkt()
        if not token_jkt or proof_jkt != token_jkt:
            raise InvalidDPoPKeyBindingError(algs=self.proof_validator.algs)
