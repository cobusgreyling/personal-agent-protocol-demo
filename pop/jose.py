"""ES256 JWTs, DPoP proofs, and PKCE for the local Poppy visit.

The draft requires ES256 for agent assertions and DPoP proofs. These helpers
sign and check that shape. Session tokens and account tokens are opaque; this
module never builds them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

JWT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_json(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64url(raw)


def generate_p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey, kid: str | None = None) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("d"):
        raise JoseError("DPoP jwk must be a public key")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise JoseError("only P-256 keys are accepted")
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def thumbprint(jwk: dict[str, Any]) -> str:
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    digest = hashlib.sha256(json.dumps(members, separators=(",", ":"), sort_keys=True).encode())
    return b64url(digest.digest())


def sign_jwt(
    key: ec.EllipticCurvePrivateKey,
    payload: dict[str, Any],
    *,
    header: dict[str, Any] | None = None,
) -> str:
    head = {"alg": "ES256", "typ": "JWT"}
    if header:
        head.update(header)
        head["alg"] = "ES256"
    signing_input = f"{b64url_json(head)}.{b64url_json(payload)}".encode("ascii")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64url(raw)


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        head_b, payload_b, sig_b = token.split(".")
    except ValueError as exc:
        raise JoseError("malformed jwt") from exc
    try:
        header = json.loads(b64url_decode(head_b))
        payload = json.loads(b64url_decode(payload_b))
    except (json.JSONDecodeError, ValueError) as exc:
        raise JoseError("malformed jwt") from exc
    header["_signing_input"] = f"{head_b}.{payload_b}".encode("ascii")
    header["_signature"] = b64url_decode(sig_b)
    return header, payload


def verify_jwt(token: str, public_key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    header, payload = decode_jwt(token)
    if header.get("alg") != "ES256":
        raise JoseError("alg is not ES256")
    signature = header["_signature"]
    if len(signature) != 64:
        raise JoseError("bad signature length")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der = encode_dss_signature(r, s)
    try:
        public_key.verify(der, header["_signing_input"], ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        raise JoseError("bad signature") from exc
    return payload


def jwt_claims(token: str) -> dict[str, Any]:
    _header, payload = decode_jwt(token)
    return payload


def dpop_proof(
    key: ec.EllipticCurvePrivateKey,
    jwk: dict[str, str],
    method: str,
    url: str,
    *,
    access_token: str | None = None,
    nonce: str | None = None,
    jti: str,
) -> str:
    payload: dict[str, Any] = {
        "jti": jti,
        "htm": method.upper(),
        "htu": url.split("?", 1)[0].split("#", 1)[0],
        "iat": int(time.time()),
    }
    if access_token is not None:
        payload["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    if nonce:
        payload["nonce"] = nonce
    return sign_jwt(key, payload, header={"typ": "dpop+jwt", "jwk": {k: v for k, v in jwk.items() if k != "kid"}})


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


class JoseError(Exception):
    pass
