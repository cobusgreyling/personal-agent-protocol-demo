"""Cedar Line, a fictional shop that speaks Personal Agent Protocol draft 0.1.

One process serves discovery, the OAuth endpoints, a small OpenAPI, and the
company agent. Tokens stay in memory and die with the process.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import hashlib as _hashlib

from pop.jose import (
    CLIENT_ASSERTION_TYPE,
    JWT,
    JoseError,
    b64url,
    public_key_from_jwk,
    thumbprint,
    verify_jwt,
)

from pop.pages import consent_page


ACCOUNT = {
    "id": "acct_alex",
    "label": "Alex Mora",
    "email": "alex.mora@cedarline.example",
}
ORDER_ID = "CL-1042"
FIELD_SKU = "field-jacket-m"
INSULATED_SKU = "field-insulated-m"
PRICE_DIFFERENCE = 48

CATALOG = [
    {"sku": FIELD_SKU, "name": "Field jacket", "size": "medium", "warmth": "shell", "price_usd": 220},
    {"sku": INSULATED_SKU, "name": "Insulated field jacket", "size": "medium", "warmth": "insulated", "price_usd": 268},
]


def _now() -> int:
    return int(time.time())


def _id(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(12)


def _rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Company:
    def __init__(self) -> None:
        self.origin = ""
        self.lock = threading.Lock()
        self.clients: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, Any] = {}
        self.seen_jti: dict[str, int] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.access: dict[str, dict[str, Any]] = {}
        self.accounts: dict[str, dict[str, Any]] = {}
        self.auth_requests: dict[str, dict[str, Any]] = {}
        self.codes: dict[str, dict[str, Any]] = {}
        self.conversations: dict[str, dict[str, Any]] = {}
        self.message_index: dict[tuple[str, str], dict[str, Any]] = {}
        self.idempotency: dict[tuple[str, str], tuple[str, int, dict[str, Any]]] = {}
        self.order = {
            "id": ORDER_ID,
            "item_id": "itm_field",
            "sku": FIELD_SKU,
            "name": "Field jacket",
            "size": "medium",
            "status": "delivered",
            "exchanged": False,
        }

    def poppy_document(self) -> dict[str, Any]:
        origin = self.origin
        return {
            "protocol_version": "0.1",
            "organization": {"name": "Cedar Line", "domain": "127.0.0.1"},
            "auth": {
                "issuer": origin,
                "direct": {"scopes": ["poppy:read", "poppy:write"]},
            },
            "agent": {
                "protocols": [
                    {"type": "poppy", "endpoint": f"{origin}/poppy/conversations"}
                ]
            },
            "apis": [
                {
                    "type": "openapi",
                    "url": f"{origin}/openapi.json",
                    "description": "Catalog and orders",
                }
            ],
        }

    def oauth_metadata(self) -> dict[str, Any]:
        origin = self.origin
        return {
            "issuer": origin,
            "token_endpoint": f"{origin}/oauth/token",
            "revocation_endpoint": f"{origin}/oauth/revoke",
            "authorization_endpoint": f"{origin}/oauth/authorize",
            "poppy_domains": ["127.0.0.1"],
        }

    def openapi(self) -> dict[str, Any]:
        return {
            "openapi": "3.1.0",
            "info": {"title": "Cedar Line", "version": "0.1"},
            "paths": {
                "/catalog": {
                    "get": {
                        "summary": "Search products. A signed-out session may call this.",
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}}
                        ],
                    }
                },
                "/orders/{order_id}": {
                    "get": {"summary": "View one order. Requires poppy:read."}
                },
                "/orders/{order_id}/exchanges": {
                    "post": {"summary": "Exchange an item. Requires poppy:write."}
                },
            },
        }

    def ledger(self) -> dict[str, Any]:
        with self.lock:
            sessions = []
            for session in self.sessions.values():
                client = self.clients.get(session["client_id"], {})
                sessions.append(
                    {
                        "session_id": session["session_id"],
                        "client_name": client.get("client_name", "Unknown agent"),
                        "client_id": session["client_id"],
                        "user_id": session["user_id"],
                        "signed_in": session["signed_in"],
                        "account": ACCOUNT["label"] if session["signed_in"] else None,
                        "scopes": list(session["scopes"]),
                    }
                )
            return {"sessions": sessions, "order": dict(self.order)}

    def _forget_expired_jti(self) -> None:
        cutoff = _now() - 120
        self.seen_jti = {jti: exp for jti, exp in self.seen_jti.items() if exp >= cutoff}

    def _take_jti(self, jti: str, exp: int, error: str) -> None:
        self._forget_expired_jti()
        if not jti or len(jti) < 16:
            raise CompanyError(400, error, "jti must be at least 128 bits")
        if jti in self.seen_jti:
            raise CompanyError(400, error, "this jti was already used")
        self.seen_jti[jti] = exp

    def _load_client(self, client_id: str) -> dict[str, Any]:
        if client_id in self.clients:
            return self.clients[client_id]
        if not client_id.startswith("https://") and not client_id.startswith("http://127.0.0.1:"):
            raise CompanyError(401, "invalid_client", "client_id must be the metadata URL")
        try:
            with urllib.request.urlopen(client_id, timeout=3) as response:
                metadata = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            raise CompanyError(401, "invalid_client", "client metadata could not be fetched") from exc
        if metadata.get("client_id") != client_id:
            raise CompanyError(401, "invalid_client", "client_id does not match the fetched document")
        jwks_uri = metadata.get("jwks_uri", "")
        try:
            with urllib.request.urlopen(jwks_uri, timeout=3) as response:
                jwks = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            raise CompanyError(401, "invalid_client", "jwks could not be fetched") from exc
        keys = {}
        for jwk in jwks.get("keys", []):
            if "d" in jwk:
                raise CompanyError(401, "invalid_client", "jwks must contain only public keys")
            keys[jwk.get("kid", "")] = public_key_from_jwk(jwk)
        self.clients[client_id] = metadata
        self.keys[client_id] = keys
        return metadata

    def _client_key(self, client_id: str, kid: str | None) -> Any:
        keys = self.keys[client_id]
        if kid and kid in keys:
            return keys[kid]
        if len(keys) == 1:
            return next(iter(keys.values()))
        raise CompanyError(401, "invalid_client", "no matching key")

    def _check_client_assertion(self, form: dict[str, str], audience: str) -> tuple[str, dict[str, Any]]:
        client_id = form.get("client_id", "")
        if form.get("client_assertion_type") != CLIENT_ASSERTION_TYPE:
            raise CompanyError(401, "invalid_client", "client_assertion_type is not private_key_jwt")
        token = form.get("client_assertion", "")
        metadata = self._load_client(client_id)
        try:
            header, _payload = _unsafe_header(token)
            payload = verify_jwt(token, self._client_key(client_id, header.get("kid")))
        except (JoseError, KeyError) as exc:
            raise CompanyError(401, "invalid_client", "client assertion did not verify") from exc
        self._check_assertion_claims(payload, iss=client_id, aud=audience, sub=client_id)
        return client_id, metadata

    def _check_assertion_claims(self, payload: dict[str, Any], *, iss: str, aud: str, sub: str | None = None) -> None:
        now = _now()
        if payload.get("iss") != iss:
            raise CompanyError(400, "invalid_grant", "iss does not match")
        if payload.get("aud") != aud:
            raise CompanyError(400, "invalid_grant", "aud does not match the token endpoint")
        if sub is not None and payload.get("sub") != sub:
            raise CompanyError(400, "invalid_grant", "sub does not match")
        exp = int(payload.get("exp", 0))
        iat = int(payload.get("iat", 0))
        if exp <= now or exp - iat > 120 or iat > now + 30:
            raise CompanyError(400, "invalid_grant", "assertion is expired or too long-lived")
        self._take_jti(str(payload.get("jti", "")), exp, "invalid_grant")

    def _check_dpop(self, proof: str, method: str, url: str, access_token: str | None) -> str:
        if not proof:
            raise CompanyError(400, "invalid_dpop_proof", "DPoP proof is missing")
        try:
            header, _ = _unsafe_header(proof)
            if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
                raise JoseError("bad dpop header")
            jwk = header.get("jwk") or {}
            payload = verify_jwt(proof, public_key_from_jwk(jwk))
        except (JoseError, KeyError, ValueError) as exc:
            raise CompanyError(400, "invalid_dpop_proof", "DPoP proof did not verify") from exc
        now = _now()
        iat = int(payload.get("iat", 0))
        if abs(now - iat) > 60:
            raise CompanyError(400, "invalid_dpop_proof", "DPoP iat is outside the window")
        if payload.get("htm") != method.upper() or payload.get("htu") != url.split("?")[0]:
            raise CompanyError(400, "invalid_dpop_proof", "htm or htu does not match")
        if access_token is None:
            if "ath" in payload:
                raise CompanyError(400, "invalid_dpop_proof", "token request proof must not include ath")
        else:
            expected = b64url(_hashlib.sha256(access_token.encode("ascii")).digest())
            if payload.get("ath") != expected:
                raise CompanyError(400, "invalid_dpop_proof", "ath does not match the session token")
        self._take_jti(str(payload.get("jti", "")), iat + 120, "invalid_dpop_proof")
        return thumbprint(jwk)

    def _issue_access(self, session: dict[str, Any], cnf: str) -> dict[str, Any]:
        token = secrets.token_urlsafe(32)
        signed_in = bool(session["signed_in"])
        scope = " ".join(session["scopes"]) if signed_in else ""
        self.access[token] = {
            "session_id": session["session_id"],
            "cnf": cnf,
            "signed_in": signed_in,
            "scope": scope,
            "exp": _now() + 3600,
        }
        body: dict[str, Any] = {
            "access_token": token,
            "token_type": "DPoP",
            "expires_in": 3600,
            "scope": scope,
            "session_id": session["session_id"],
            "signed_in": signed_in,
        }
        return body

    def _bearer(self, header: str) -> tuple[str, str]:
        if not header.startswith("DPoP "):
            raise CompanyError(401, "invalid_token", "session token must use the DPoP scheme")
        return "DPoP", header[5:].strip()

    def _session_from_request(self, authorization: str, proof: str, method: str, url: str) -> tuple[dict[str, Any], dict[str, Any]]:
        _scheme, token = self._bearer(authorization)
        cnf = self._check_dpop(proof, method, url, token)
        record = self.access.get(token)
        if record is None or record["exp"] <= _now():
            raise CompanyError(401, "invalid_token", "session token is missing or expired")
        if record["cnf"] != cnf:
            raise CompanyError(400, "invalid_dpop_proof", "proof key does not match the session token")
        session = self.sessions.get(record["session_id"])
        if session is None:
            raise CompanyError(400, "invalid_session", "session has ended")
        return session, record

    def effective_scopes(self, session: dict[str, Any], record: dict[str, Any]) -> set[str]:
        if not record["signed_in"] or not session["signed_in"]:
            return set()
        issued = set(record["scope"].split()) if record["scope"] else set()
        return issued & set(session["scopes"])

    def require_scope(self, session: dict[str, Any], record: dict[str, Any], scope: str) -> None:
        if not record["signed_in"] or not session["signed_in"]:
            raise CompanyError(403, "sign_in_required", "this request needs a signed-in session")
        if scope not in self.effective_scopes(session, record):
            raise CompanyError(403, "insufficient_scope", f"{scope} was not granted", scope=scope)

    def start_session(self, form: dict[str, str], proof: str) -> dict[str, Any]:
        audience = self.oauth_metadata()["token_endpoint"]
        with self.lock:
            client_id, _metadata = self._check_client_assertion(form, audience)
            cnf = self._check_dpop(proof, "POST", audience, None)
            if form.get("grant_type") != JWT:
                raise CompanyError(400, "invalid_grant", "grant_type is not jwt-bearer")
            try:
                header, _ = _unsafe_header(form.get("assertion", ""))
                user_claims = verify_jwt(form.get("assertion", ""), self._client_key(client_id, header.get("kid")))
            except (JoseError, KeyError) as exc:
                raise CompanyError(400, "invalid_grant", "user assertion did not verify") from exc
            self._check_assertion_claims(user_claims, iss=client_id, aud=audience)
            user_id = str(user_claims.get("sub", ""))
            if not user_id or "@" in user_id or user_id.startswith("http"):
                raise CompanyError(400, "invalid_grant", "user id must be opaque")
            session_id = form.get("session_id", "")
            if session_id:
                session = self.sessions.get(session_id)
                if session is None or session["client_id"] != client_id or session["user_id"] != user_id:
                    raise CompanyError(400, "invalid_session", "session does not belong to this agent and user")
                if session["signed_in"]:
                    raise CompanyError(400, "invalid_grant", "a signed-in session is renewed with the account token")
            else:
                session = {
                    "session_id": _id("ses_"),
                    "client_id": client_id,
                    "user_id": user_id,
                    "signed_in": False,
                    "scopes": [],
                    "account_token": None,
                }
                self.sessions[session["session_id"]] = session
            return self._issue_access(session, cnf)

    def refresh(self, form: dict[str, str], proof: str) -> dict[str, Any]:
        audience = self.oauth_metadata()["token_endpoint"]
        with self.lock:
            client_id, _metadata = self._check_client_assertion(form, audience)
            cnf = self._check_dpop(proof, "POST", audience, None)
            account = self.accounts.get(form.get("refresh_token", ""))
            if account is None or account["client_id"] != client_id or account["revoked"]:
                raise CompanyError(400, "invalid_grant", "account token is missing, revoked, or for another agent")
            if account["exp"] <= _now():
                raise CompanyError(400, "invalid_grant", "account token has expired")
            requested = form.get("scope", "").split()
            if any(scope not in account["scopes"] for scope in requested):
                raise CompanyError(400, "invalid_scope", "scope is broader than the account token")
            scopes = requested or list(account["scopes"])
            session_id = form.get("session_id", "")
            if session_id:
                session = self.sessions.get(session_id)
                if session is None or session["client_id"] != client_id or session["user_id"] != account["user_id"]:
                    raise CompanyError(400, "invalid_session", "session does not belong to this account")
                if session["signed_in"] and session.get("account_id") not in (None, account["account_id"]):
                    raise CompanyError(400, "account_mismatch", "session is signed in to a different account")
            else:
                session = {
                    "session_id": _id("ses_"),
                    "client_id": client_id,
                    "user_id": account["user_id"],
                    "signed_in": False,
                    "scopes": [],
                    "account_token": None,
                    "account_id": account["account_id"],
                }
                self.sessions[session["session_id"]] = session
            session["signed_in"] = True
            session["scopes"] = scopes
            session["account_id"] = account["account_id"]
            session["account_token"] = form.get("refresh_token")
            return self._issue_access(session, cnf)

    def begin_authorization(self, query: dict[str, str]) -> dict[str, Any]:
        client_id = query.get("client_id", "")
        metadata = self._load_client(client_id)
        redirect_uri = query.get("redirect_uri", "")
        if redirect_uri not in metadata.get("redirect_uris", []):
            raise CompanyError(400, "invalid_request", "redirect_uri is not registered")
        if query.get("response_type") != "code":
            raise CompanyError(400, "invalid_request", "response_type must be code")
        if query.get("code_challenge_method") != "S256" or not query.get("code_challenge"):
            raise CompanyError(400, "invalid_request", "PKCE S256 is required")
        allowed = set(self.poppy_document()["auth"]["direct"]["scopes"])
        requested = [scope for scope in query.get("scope", "").split() if scope]
        if not requested or any(scope not in allowed for scope in requested):
            raise CompanyError(400, "invalid_scope", "scope is missing or not offered for direct sign-in")
        request_id = _id("az_")
        with self.lock:
            self.auth_requests[request_id] = {
                "client_id": client_id,
                "client_name": metadata.get("client_name", "Personal agent"),
                "redirect_uri": redirect_uri,
                "state": query.get("state", ""),
                "code_challenge": query["code_challenge"],
                "requested": requested,
                "exp": _now() + 600,
            }
        return self.auth_requests[request_id] | {"request_id": request_id}

    def submit_authorization(self, request_id: str, decision: str) -> str:
        with self.lock:
            pending = self.auth_requests.get(request_id)
            if pending is None or pending["exp"] <= _now():
                raise CompanyError(400, "invalid_grant", "sign-in request has expired")
            issuer = self.oauth_metadata()["issuer"]
            params = {"state": pending["state"], "iss": issuer}
            if decision == "deny":
                params["error"] = "access_denied"
            else:
                granted = list(pending["requested"])
                if decision == "read":
                    granted = [scope for scope in granted if scope == "poppy:read"]
                if not granted:
                    raise CompanyError(400, "invalid_scope", "nothing to grant")
                code = secrets.token_urlsafe(24)
                self.codes[code] = {
                    "client_id": pending["client_id"],
                    "redirect_uri": pending["redirect_uri"],
                    "code_challenge": pending["code_challenge"],
                    "scopes": granted,
                    "account_id": ACCOUNT["id"],
                    "exp": _now() + 600,
                    "used": False,
                }
                params["code"] = code
            del self.auth_requests[request_id]
            return pending["redirect_uri"] + "?" + urllib.parse.urlencode(params)

    def exchange_code(self, form: dict[str, str], proof: str) -> dict[str, Any]:
        audience = self.oauth_metadata()["token_endpoint"]
        with self.lock:
            client_id, _metadata = self._check_client_assertion(form, audience)
            cnf = self._check_dpop(proof, "POST", audience, None)
            code = self.codes.get(form.get("code", ""))
            if code is None or code["used"] or code["exp"] <= _now() or code["client_id"] != client_id:
                raise CompanyError(400, "invalid_grant", "code is missing, reused, or expired")
            if form.get("redirect_uri") != code["redirect_uri"]:
                raise CompanyError(400, "invalid_grant", "redirect_uri does not match")
            verifier = form.get("code_verifier", "")
            if b64url(_hashlib.sha256(verifier.encode("ascii")).digest()) != code["code_challenge"]:
                raise CompanyError(400, "invalid_grant", "code_verifier does not match")
            session = self.sessions.get(form.get("session_id", ""))
            if session is None or session["client_id"] != client_id:
                raise CompanyError(400, "invalid_session", "session does not belong to this agent")
            if session["signed_in"] and session.get("account_id") not in (None, code["account_id"]):
                raise CompanyError(400, "account_mismatch", "session is signed in to a different account")
            code["used"] = True
            previous = session.get("account_token")
            refresh = _id("pat_")
            self.accounts[refresh] = {
                "client_id": client_id,
                "user_id": session["user_id"],
                "account_id": code["account_id"],
                "scopes": list(code["scopes"]),
                "exp": _now() + 30 * 24 * 3600,
                "revoked": False,
            }
            session["signed_in"] = True
            session["scopes"] = list(code["scopes"])
            session["account_id"] = code["account_id"]
            session["account_token"] = refresh
            body = self._issue_access(session, cnf)
            body["refresh_token"] = refresh
            body["refresh_token_expires_in"] = 30 * 24 * 3600
            body["replaced_account_token"] = previous
            return body

    def revoke(self, form: dict[str, str]) -> None:
        audience = self.oauth_metadata()["revocation_endpoint"]
        with self.lock:
            client_id, _metadata = self._check_client_assertion(form, audience)
            # The revocation audience in the draft's example is the revocation
            # endpoint itself. Agents in this demo sign the client assertion
            # for that URL.
            account = self.accounts.get(form.get("token", ""))
            if account is None or account["client_id"] != client_id:
                return
            account["revoked"] = True
            for session in self.sessions.values():
                if session.get("account_token") == form.get("token"):
                    session["signed_in"] = False
                    session["scopes"] = []
                    session["account_token"] = None

    def catalog(self, session: dict[str, Any], record: dict[str, Any], query: str) -> dict[str, Any]:
        del session, record
        needle = query.lower()
        products = []
        for item in CATALOG:
            haystack = " ".join([item["name"], item["warmth"], item["sku"]]).lower()
            if not needle or needle in haystack or ("warm" in needle and item["warmth"] == "insulated"):
                products.append(item)
        return {"products": products}

    def read_order(self, session: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        self.require_scope(session, record, "poppy:read")
        return dict(self.order)

    def exchange(self, session: dict[str, Any], record: dict[str, Any], body: dict[str, Any], idempotency_key: str) -> tuple[int, dict[str, Any]]:
        self.require_scope(session, record, "poppy:write")
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
        cache_key = (session["session_id"], idempotency_key)
        if idempotency_key:
            cached = self.idempotency.get(cache_key)
            if cached is not None:
                if cached[0] != raw:
                    raise CompanyError(409, "idempotency_mismatch", "this Idempotency-Key was used with a different body")
                return cached[1], cached[2]
        if body.get("item_id") != self.order["item_id"] or body.get("replacement_sku") != INSULATED_SKU:
            raise CompanyError(400, "invalid_request", "Cedar Line can exchange this jacket only for the insulated one")
        changed = not self.order["exchanged"]
        self.order["sku"] = INSULATED_SKU
        self.order["name"] = "Insulated field jacket"
        self.order["exchanged"] = True
        result = {
            "order": dict(self.order),
            "changed": changed,
            "price_difference_usd": PRICE_DIFFERENCE,
        }
        if idempotency_key:
            self.idempotency[cache_key] = (raw, 200, result)
        return 200, result

    def accept_message(
        self,
        session: dict[str, Any],
        record: dict[str, Any],
        conversation_id: str | None,
        message: dict[str, Any],
        *,
        wait: bool,
        cursor: str | None,
    ) -> dict[str, Any]:
        text = message.get("text", "")
        data = message.get("data")
        context = message.get("context")
        if not text and data is None and context is None:
            raise CompanyError(400, "invalid_request", "message needs text, data, or context")
        if message.get("sender") not in ("agent", "human"):
            raise CompanyError(400, "invalid_request", "sender must be agent or human")
        message_id = str(message.get("id", ""))
        if not _safe_id(message_id):
            raise CompanyError(400, "invalid_request", "message id is missing or not url-safe")
        fingerprint = json.dumps({"text": text, "data": data, "context": context, "sender": message["sender"]}, sort_keys=True)
        index_key = (session["user_id"], message_id)
        existing = self.message_index.get(index_key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise CompanyError(409, "message_id_conflict", "message id was reused with different content")
            return existing["response"]
        if conversation_id is None:
            conversation = {
                "id": _id("cnv_"),
                "client_id": session["client_id"],
                "user_id": session["user_id"],
                "account_id": session.get("account_id") if record["signed_in"] and session["signed_in"] else None,
                "events": [],
                "status": "working",
                "responder": "agent",
                "closed": False,
            }
            self.conversations[conversation["id"]] = conversation
            status_code = 201
        else:
            conversation = self._conversation_for(session, record, conversation_id)
            status_code = 202
        self._append_message(conversation, "user", message["sender"], text, data, message_id)
        reply_text, reply_data = self._reply(text)
        reply_id = _id("msg_")
        self._append_message(conversation, "company", "agent", reply_text, reply_data, reply_id)
        conversation["status"] = "idle"
        conversation["responder"] = "agent"
        conversation["events"].append(
            {
                "id": _id("evt_"),
                "type": "state",
                "created_at": _rfc3339(),
                "status": "idle",
                "responder": "agent",
            }
        )
        full = self._events_body(conversation, cursor if wait else None)
        if wait:
            response = full
        else:
            response = {
                "conversation_id": conversation["id"],
                "status": conversation["status"],
                "responder": conversation["responder"],
            }
        self.message_index[index_key] = {"fingerprint": fingerprint, "response": response, "status": status_code}
        return response

    def _reply(self, text: str) -> tuple[str, dict[str, Any] | None]:
        lowered = text.lower()
        if "exchanged" in lowered or "exchange is done" in lowered:
            return (
                "Order CL-1042 is now the insulated field jacket, medium. The difference is $48.",
                {"order_id": ORDER_ID, "sku": self.order["sku"]},
            )
        if any(word in lowered for word in ("warm", "jacket", "exchange", "insulated")):
            return (
                "The insulated field jacket would be warmer. Exchanging order CL-1042 comes to $48 more. I can do that once the account allows changes.",
                {
                    "order_id": ORDER_ID,
                    "replacement_sku": INSULATED_SKU,
                    "price_difference_usd": PRICE_DIFFERENCE,
                },
            )
        return ("Cedar Line can help with this order.", None)

    def _append_message(self, conversation: dict[str, Any], role: str, sender: str, text: str, data: dict[str, Any] | None, message_id: str) -> None:
        message: dict[str, Any] = {"id": message_id, "role": role, "sender": sender}
        if text:
            message["text"] = text
        if data is not None:
            message["data"] = data
        conversation["events"].append(
            {
                "id": _id("evt_"),
                "type": "message",
                "created_at": _rfc3339(),
                "message": message,
            }
        )

    def _conversation_for(self, session: dict[str, Any], record: dict[str, Any], conversation_id: str) -> dict[str, Any]:
        conversation = self.conversations.get(conversation_id)
        if conversation is None or conversation["client_id"] != session["client_id"] or conversation["user_id"] != session["user_id"]:
            raise CompanyError(404, "conversation_not_found", "no such conversation")
        if conversation.get("account_id") and not (record["signed_in"] and session["signed_in"]):
            raise CompanyError(403, "sign_in_required", "this conversation has used the account")
        if record["signed_in"] and session["signed_in"] and conversation.get("account_id") is None:
            conversation["account_id"] = session.get("account_id")
        return conversation

    def _events_body(self, conversation: dict[str, Any], cursor: str | None) -> dict[str, Any]:
        events = conversation["events"]
        if cursor:
            ids = [event["id"] for event in events]
            if cursor not in ids:
                raise CompanyError(400, "cursor_expired", "cursor is not in this conversation")
            events = events[ids.index(cursor) + 1 :]
        last = events[-1]["id"] if events else cursor
        return {
            "conversation_id": conversation["id"],
            "events": events,
            "cursor": last,
            "has_more": False,
            "status": conversation["status"],
            "responder": conversation["responder"],
        }

    def read_events(self, session: dict[str, Any], record: dict[str, Any], conversation_id: str, cursor: str | None) -> dict[str, Any]:
        conversation = self._conversation_for(session, record, conversation_id)
        return self._events_body(conversation, cursor)


def _safe_id(value: str) -> bool:
    if not value or len(value) > 256:
        return False
    return all(char.isalnum() or char in "-_" for char in value)


def _unsafe_header(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    from pop.jose import decode_jwt

    return decode_jwt(token)


class CompanyError(Exception):
    def __init__(self, status: int, error: str, description: str = "", scope: str = "") -> None:
        super().__init__(description or error)
        self.status = status
        self.error = error
        self.description = description or error
        self.scope = scope


class CompanyServer(ThreadingHTTPServer):
    def __init__(self, company: Company, port: int) -> None:
        super().__init__(("127.0.0.1", port), CompanyHandler)
        self.company = company
        company.origin = f"http://127.0.0.1:{self.server_address[1]}"


class CompanyHandler(BaseHTTPRequestHandler):
    server: CompanyServer

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    @property
    def company(self) -> Company:
        return self.server.company

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def _route(self, method: str) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = {key: values[-1] for key, values in urllib.parse.parse_qs(parsed.query).items()}
        url = self.company.origin + path
        try:
            if method == "GET" and path == "/.well-known/poppy.json":
                self._json(200, self.company.poppy_document())
            elif method == "GET" and path == "/.well-known/oauth-authorization-server":
                self._json(200, self.company.oauth_metadata())
            elif method == "GET" and path == "/openapi.json":
                self._json(200, self.company.openapi())
            elif method == "GET" and path == "/demo/ledger":
                self._json(200, self.company.ledger())
            elif method == "GET" and path == "/oauth/authorize":
                self._authorize(query)
            elif method == "POST" and path == "/oauth/authorize":
                self._authorize_submit()
            elif method == "POST" and path == "/oauth/token":
                self._token(url)
            elif method == "POST" and path == "/oauth/revoke":
                self._revoke()
            elif method == "GET" and path == "/catalog":
                self._catalog(url, query)
            elif method == "GET" and path == f"/orders/{ORDER_ID}":
                self._order(url)
            elif method == "POST" and path == f"/orders/{ORDER_ID}/exchanges":
                self._exchange(url)
            elif method == "POST" and path == "/poppy/conversations":
                self._conversation(url, None, query)
            elif path.startswith("/poppy/conversations/"):
                self._conversation_path(method, url, path, query)
            else:
                self._json(404, {"error": "not_found"})
        except CompanyError as exc:
            self._fail(exc)
        except Exception as exc:
            self._json(500, {"error": "server_error", "error_description": str(exc)})

    def _authorize(self, query: dict[str, str]) -> None:
        pending = self.company.begin_authorization(query)
        page = consent_page(
            client_name=pending["client_name"],
            client_id=pending["client_id"],
            request_id=pending["request_id"],
            requested=pending["requested"],
            account_label=ACCOUNT["label"],
            account_email=ACCOUNT["email"],
        )
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorize_submit(self) -> None:
        form = self._form()
        location = self.company.submit_authorization(form.get("request_id", ""), form.get("decision", "deny"))
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _token(self, url: str) -> None:
        form = self._form()
        proof = self.headers.get("DPoP", "")
        grant = form.get("grant_type", "")
        if grant == JWT:
            body = self.company.start_session(form, proof)
        elif grant == "authorization_code":
            body = self.company.exchange_code(form, proof)
        elif grant == "refresh_token":
            body = self.company.refresh(form, proof)
        else:
            raise CompanyError(400, "unsupported_grant_type", "grant_type is not supported")
        public = dict(body)
        public.pop("replaced_account_token", None)
        self._json(200, public, no_store=True)

    def _revoke(self) -> None:
        self.company.revoke(self._form())
        self.send_response(200)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _catalog(self, url: str, query: dict[str, str]) -> None:
        session, record = self._authenticated("GET", url)
        self._json(200, self.company.catalog(session, record, query.get("q", "")))

    def _order(self, url: str) -> None:
        session, record = self._authenticated("GET", url)
        self._json(200, self.company.read_order(session, record))

    def _exchange(self, url: str) -> None:
        session, record = self._authenticated("POST", url)
        status, body = self.company.exchange(session, record, self._json_body(), self.headers.get("Idempotency-Key", ""))
        self._json(status, body)

    def _conversation(self, url: str, conversation_id: str | None, query: dict[str, str]) -> None:
        session, record = self._authenticated("POST", url)
        message = self._json_body().get("message") or {}
        with self.company.lock:
            body = self.company.accept_message(
                session,
                record,
                conversation_id,
                message,
                wait="wait" in query,
                cursor=query.get("cursor"),
            )
        self._json(201 if conversation_id is None else 202, body)

    def _conversation_path(self, method: str, url: str, path: str, query: dict[str, str]) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 4:
            self._json(404, {"error": "not_found"})
            return
        conversation_id, action = parts[2], parts[3]
        if method == "POST" and action == "messages":
            self._conversation(url, conversation_id, query)
            return
        if method == "GET" and action == "events":
            session, record = self._authenticated("GET", url)
            with self.company.lock:
                body = self.company.read_events(session, record, conversation_id, query.get("cursor"))
            self._json(200, body)
            return
        self._json(404, {"error": "not_found"})

    def _authenticated(self, method: str, url: str) -> tuple[dict[str, Any], dict[str, Any]]:
        with self.company.lock:
            return self.company._session_from_request(self.headers.get("Authorization", ""), self.headers.get("DPoP", ""), method, url)

    def _form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {key: values[-1] for key, values in parsed.items()}

    def _json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise CompanyError(400, "invalid_request", "body is not JSON") from exc
        if not isinstance(body, dict):
            raise CompanyError(400, "invalid_request", "body must be a JSON object")
        return body

    def _fail(self, exc: CompanyError) -> None:
        parts = [f'error="{exc.error}"']
        if exc.scope:
            parts.append(f'scope="{exc.scope}"')
        header = "DPoP " + ", ".join(parts)
        body = {"error": exc.error, "error_description": exc.description}
        if exc.scope:
            body["scope"] = exc.scope
        self._json(exc.status, body, www=header, no_store=True)

    def _json(self, status: int, body: dict[str, Any], *, www: str | None = None, no_store: bool = False) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store" if no_store else "no-cache")
        if www:
            self.send_header("WWW-Authenticate", www)
        self.end_headers()
        self.wfile.write(raw)


def serve_company(port: int = 0) -> tuple[Company, CompanyServer, threading.Thread]:
    company = Company()
    httpd = CompanyServer(company, port)
    thread = threading.Thread(target=httpd.serve_forever, name="cedar-line", daemon=True)
    thread.start()
    return company, httpd, thread
