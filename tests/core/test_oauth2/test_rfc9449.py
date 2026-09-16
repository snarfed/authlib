"""Tests for RFC 9449 DPoP proof validation."""

import hashlib
import time
from base64 import urlsafe_b64encode

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6749 import InvalidGrantError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750 import InvalidTokenError
from authlib.oauth2.rfc9449 import DPoPGrantExtension
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import HMACDPoPNonceGenerator
from authlib.oauth2.rfc9449 import InvalidDPoPKeyBindingError
from authlib.oauth2.rfc9449 import InvalidDPoPProofError
from authlib.oauth2.rfc9449 import UseDPoPNonceError
from authlib.oauth2.rfc9449 import normalize_url

TOKEN_ENDPOINT = "https://server.example/token"
RESOURCE = "https://rs.example/api"


@pytest.fixture
def key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def rsa_key():
    return RSAKey.generate_key(2048)


def make_proof(key, method, url, alg="ES256", typ="dpop+jwt", jwk=None, **claims):
    header = {
        "typ": typ,
        "alg": alg,
        "jwk": key.as_dict(private=False) if jwk is None else jwk,
    }
    payload = {
        "jti": claims.pop("jti", f"jti-{time.time_ns()}"),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
    }
    payload.update(claims)
    return jwt.encode(header, payload, key)


def make_request(proof, method="POST", uri=TOKEN_ENDPOINT):
    return OAuth2Request(method, uri, headers={"DPoP": proof})


def ath_of(access_token):
    digest = hashlib.sha256(access_token.encode()).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_valid_proof_returns_thumbprint(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    assert validator.validate_proof(make_request(proof)) == key.thumbprint()


def test_missing_proof_rejected():
    validator = DPoPProofValidator()
    request = OAuth2Request("POST", TOKEN_ENDPOINT, headers={})
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_proof(request)


def test_multiple_proofs_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_proof(make_request(f"{proof},{proof}"))


def test_validator_is_stateless_across_requests(key):
    """A resource request must not leave an ``ath`` requirement behind."""
    validator = DPoPProofValidator()
    access_token = "an-access-token"

    resource_proof = make_proof(key, "GET", RESOURCE, ath=ath_of(access_token))
    validator.validate_proof(
        make_request(resource_proof, "GET", RESOURCE),
        access_token=access_token,
        for_resource=True,
    )

    token_proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    assert validator.validate_proof(make_request(token_proof)) == key.thumbprint()


def test_replayed_jti_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, jti="fixed-jti")
    validator.validate_proof(make_request(proof))
    with pytest.raises(InvalidDPoPProofError, match="replay"):
        validator.validate_proof(make_request(proof))


def test_stale_iat_rejected(key):
    validator = DPoPProofValidator(iat_leeway=30)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, iat=int(time.time()) - 600)
    with pytest.raises(InvalidDPoPProofError, match="iat"):
        validator.validate_proof(make_request(proof))


def test_future_iat_rejected(key):
    validator = DPoPProofValidator(iat_leeway=30)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, iat=int(time.time()) + 600)
    with pytest.raises(InvalidDPoPProofError, match="iat"):
        validator.validate_proof(make_request(proof))


@pytest.mark.parametrize(
    ("proof_url", "request_url"),
    [
        ("https://Server.Example/token", "https://server.example/token"),
        ("https://server.example:443/token", "https://server.example/token"),
        ("https://server.example/token?foo=bar", "https://server.example/token"),
        ("https://server.example/token#frag", "https://server.example/token"),
    ],
)
def test_htu_normalization(key, proof_url, request_url):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", proof_url)
    request = OAuth2Request("POST", request_url, headers={"DPoP": proof})
    assert validator.validate_proof(request) == key.thumbprint()


def test_htu_mismatch_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", "https://evil.example/token")
    with pytest.raises(InvalidDPoPProofError, match="htu"):
        validator.validate_proof(make_request(proof))


def test_htm_mismatch_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "GET", TOKEN_ENDPOINT)
    with pytest.raises(InvalidDPoPProofError, match="htm"):
        validator.validate_proof(make_request(proof))


def test_wrong_typ_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, typ="JWT")
    with pytest.raises(InvalidDPoPProofError, match="typ"):
        validator.validate_proof(make_request(proof))


def test_alg_not_allowed_rejected(key):
    validator = DPoPProofValidator(algs=["ES384"])
    proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    with pytest.raises(InvalidDPoPProofError, match="alg"):
        validator.validate_proof(make_request(proof))


def test_rsa_proof_accepted(rsa_key):
    """An RSA key in the jwk header is larger than joserfc's default limit."""
    validator = DPoPProofValidator(algs=["RS256"])
    proof = make_proof(rsa_key, "POST", TOKEN_ENDPOINT, alg="RS256")
    assert validator.validate_proof(make_request(proof)) == rsa_key.thumbprint()


def test_rsa_proof_with_alg_not_allowed_reports_alg(rsa_key):
    """Naming the alg, not the size, is what tells the client what to fix."""
    validator = DPoPProofValidator()
    proof = make_proof(rsa_key, "POST", TOKEN_ENDPOINT, alg="RS256")
    with pytest.raises(InvalidDPoPProofError, match="alg"):
        validator.validate_proof(make_request(proof))


def test_oversized_header_rejected(key):
    validator = DPoPProofValidator(max_header_length=64)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    with pytest.raises(InvalidDPoPProofError, match="well-formed"):
        validator.validate_proof(make_request(proof))


def test_symmetric_alg_rejected():
    """A symmetric alg must never be accepted, even if the signature verifies."""
    validator = DPoPProofValidator(algs=["HS256"])
    key = OctKey.import_key("a" * 32)
    header = {"typ": "dpop+jwt", "alg": "HS256", "jwk": key.as_dict()}
    payload = {
        "jti": "x",
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": int(time.time()),
    }
    proof = jwt.encode(header, payload, key)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_proof(make_request(proof))


def test_private_key_in_header_rejected(key):
    validator = DPoPProofValidator()
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, jwk=key.as_dict(private=True))
    with pytest.raises(InvalidDPoPProofError, match="public"):
        validator.validate_proof(make_request(proof))


def test_signature_from_other_key_rejected(key):
    """The jwk header must be the key that actually signed the proof."""
    validator = DPoPProofValidator()
    other = ECKey.generate_key("P-256")
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, jwk=other.as_dict(private=False))
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_proof(make_request(proof))


def test_ath_required_and_checked(key):
    validator = DPoPProofValidator()
    access_token = "an-access-token"

    missing = make_proof(key, "GET", RESOURCE)
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        validator.validate_proof(
            make_request(missing, "GET", RESOURCE),
            access_token=access_token,
            for_resource=True,
        )

    wrong = make_proof(key, "GET", RESOURCE, ath=ath_of("different-token"))
    with pytest.raises(InvalidDPoPProofError, match="ath"):
        validator.validate_proof(
            make_request(wrong, "GET", RESOURCE),
            access_token=access_token,
            for_resource=True,
        )


def test_nonce_required_when_generator_configured(key):
    generator = HMACDPoPNonceGenerator("secret")
    validator = DPoPProofValidator(nonce_generator=generator)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT)
    with pytest.raises(UseDPoPNonceError) as exc:
        validator.validate_proof(make_request(proof))
    assert ("DPoP-Nonce", generator.next()) in exc.value.get_headers()


def test_valid_nonce_accepted(key):
    generator = HMACDPoPNonceGenerator("secret")
    validator = DPoPProofValidator(nonce_generator=generator)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, nonce=generator.next())
    assert validator.validate_proof(make_request(proof)) == key.thumbprint()


def test_wrong_nonce_rejected(key):
    generator = HMACDPoPNonceGenerator("secret")
    validator = DPoPProofValidator(nonce_generator=generator)
    proof = make_proof(key, "POST", TOKEN_ENDPOINT, nonce="not-a-real-nonce")
    with pytest.raises(UseDPoPNonceError):
        validator.validate_proof(make_request(proof))


def test_nonce_generator_is_deterministic_across_instances():
    """Separate workers sharing a secret must accept each other's nonces."""
    one = HMACDPoPNonceGenerator("shared-secret")
    two = HMACDPoPNonceGenerator("shared-secret")
    assert two.check(one.next())


def test_nonce_generator_rejects_other_secret():
    assert not HMACDPoPNonceGenerator("a").check(HMACDPoPNonceGenerator("b").next())


def test_nonce_generator_accepts_previous_window():
    generator = HMACDPoPNonceGenerator("secret", max_age=90)
    previous = generator._compute(generator._counter() - 1)
    assert generator.check(previous)


def test_nonce_generator_rejects_expired_window():
    generator = HMACDPoPNonceGenerator("secret", max_age=90)
    expired = generator._compute(generator._counter() - 5)
    assert not generator.check(expired)


class Token:
    def __init__(self, dpop_jkt=None, scope="profile"):
        self.dpop_jkt = dpop_jkt
        self.scope = scope

    def get_dpop_jkt(self):
        return self.dpop_jkt

    def get_scope(self):
        return self.scope

    def is_expired(self):
        return False

    def is_revoked(self):
        return False


def make_protector(token, proof_validator=None):
    validator_cls_token = token

    class Validator(DPoPTokenValidator):
        def authenticate_token(self, token_string):
            return validator_cls_token

    class Bearer(BearerTokenValidator):
        def authenticate_token(self, token_string):
            return validator_cls_token

    protector = ResourceProtector()
    protector.register_token_validator(
        Validator(proof_validator or DPoPProofValidator())
    )
    protector.register_token_validator(Bearer())
    return protector


def test_resource_protector_accepts_bound_token(key):
    access_token = "bound-token"
    token = Token(dpop_jkt=key.thumbprint())
    proof = make_proof(key, "GET", RESOURCE, ath=ath_of(access_token))
    request = OAuth2Request(
        "GET",
        RESOURCE,
        headers={"DPoP": proof, "Authorization": f"DPoP {access_token}"},
    )
    assert make_protector(token).validate_request(None, request) is token


def test_resource_protector_rejects_wrong_key(key):
    access_token = "bound-token"
    token = Token(dpop_jkt=ECKey.generate_key("P-256").thumbprint())
    proof = make_proof(key, "GET", RESOURCE, ath=ath_of(access_token))
    request = OAuth2Request(
        "GET",
        RESOURCE,
        headers={"DPoP": proof, "Authorization": f"DPoP {access_token}"},
    )
    with pytest.raises(InvalidDPoPKeyBindingError):
        make_protector(token).validate_request(None, request)


def test_bound_token_rejected_as_bearer(key):
    """A DPoP bound token must not be usable as a plain Bearer token."""
    token = Token(dpop_jkt=key.thumbprint())
    request = OAuth2Request(
        "GET", RESOURCE, headers={"Authorization": "Bearer bound-token"}
    )
    with pytest.raises(InvalidTokenError) as exc:
        make_protector(token).validate_request(None, request)
    assert any(
        "DPoP" in value
        for _, value in exc.value.get_headers()
        if isinstance(value, str)
    )


def test_unbound_token_still_works_as_bearer():
    token = Token(dpop_jkt=None)
    request = OAuth2Request(
        "GET", RESOURCE, headers={"Authorization": "Bearer plain-token"}
    )
    assert make_protector(token).validate_request(None, request) is token


class Grant:
    def __init__(self, request, authorization_code=None):
        self.request = request
        self.hooks = {}
        if authorization_code is not None:
            request.authorization_code = authorization_code

    def register_hook(self, name, hook):
        self.hooks[name] = hook

    def run(self):
        self.hooks["after_validate_token_request"](self, None)


class Code:
    def __init__(self, dpop_jkt=None):
        self.dpop_jkt = dpop_jkt

    def get_dpop_jkt(self):
        return self.dpop_jkt


def make_grant(proof=None, authorization_code=None):
    headers = {"DPoP": proof} if proof else {}
    request = OAuth2Request("POST", TOKEN_ENDPOINT, headers=headers)
    request.payload = BasicOAuth2Payload({})
    return Grant(request, authorization_code)


def test_grant_binds_jkt_from_proof(key):
    grant = make_grant(proof=make_proof(key, "POST", TOKEN_ENDPOINT))
    DPoPGrantExtension(DPoPProofValidator())(grant)
    grant.run()
    assert grant.request.payload.dpop_jkt == key.thumbprint()


def test_grant_without_dpop_is_left_alone():
    """A client not using DPoP must keep working once the extension is on."""
    grant = make_grant()
    DPoPGrantExtension(DPoPProofValidator())(grant)
    grant.run()
    assert grant.request.payload.dpop_jkt is None


def test_grant_requires_proof_for_bound_code(key):
    grant = make_grant(authorization_code=Code(dpop_jkt=key.thumbprint()))
    DPoPGrantExtension(DPoPProofValidator())(grant)
    with pytest.raises(InvalidGrantError):
        grant.run()


def test_grant_rejects_mismatched_jkt(key):
    other = ECKey.generate_key("P-256")
    grant = make_grant(
        proof=make_proof(key, "POST", TOKEN_ENDPOINT),
        authorization_code=Code(dpop_jkt=other.thumbprint()),
    )
    DPoPGrantExtension(DPoPProofValidator())(grant)
    with pytest.raises(InvalidGrantError):
        grant.run()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Server.Example/token", "https://server.example/token"),
        ("https://server.example:443/token", "https://server.example/token"),
        ("http://server.example:80/token", "http://server.example/token"),
        ("https://server.example:8443/token", "https://server.example:8443/token"),
        ("https://server.example/token?a=b#c", "https://server.example/token"),
        ("https://server.example", "https://server.example/"),
    ],
)
def test_normalize_url(url, expected):
    assert normalize_url(url) == expected
