"""Pip, a personal agent that follows a company's poppy.json.

Pip discovers Cedar Line, opens a signed-out session, and only touches the
account after the person approves access on Cedar Line's own page.
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from pop.jose import (
    CLIENT_ASSERTION_TYPE,
    JWT,
    dpop_proof,
    generate_p256,
    jwt_claims,
    pkce_challenge,
    public_jwk,
    sign_jwt,
)

USER_ID = "usr_Q7c1vK"
ORDER_ID = "CL-1042"


class ProtocolError(Exception):
    def __init__(self, status: int, error: str, description: str = "", scope: str = "") -> None:
        super().__init__(description or error)
        self.status = status
        self.error = error
        self.description = description or error
        self.scope = scope


class DiscoveryError(Exception):
    pass


def validate_discovery(document: dict[str, Any], metadata: dict[str, Any], host: str) -> None:
    """The checks draft 0.1 requires before a personal agent uses poppy.json."""
    domain = str(document.get("organization", {}).get("domain", ""))
    if domain != host and host != f"www.{domain}":
        raise DiscoveryError("organization.domain does not match the requested host")
    version = str(document.get("protocol_version", ""))
    major = version.split(".", 1)[0]
    if major != "0":
        raise DiscoveryError(f"unsupported protocol major version {version}")
    issuer = str(document.get("auth", {}).get("issuer", ""))
    if metadata.get("issuer") != issuer:
        raise DiscoveryError("oauth metadata issuer does not match auth.issuer")
    if domain not in metadata.get("poppy_domains", []):
        raise DiscoveryError("poppy_domains does not include this company")
    for name in ("token_endpoint", "revocation_endpoint", "authorization_endpoint"):
        if not metadata.get(name):
            raise DiscoveryError(f"oauth metadata is missing {name}")


class PersonalAgent:
    def __init__(self, company_origin: str, own_origin: str) -> None:
        self.company_origin = company_origin.rstrip("/")
        self.origin = own_origin.rstrip("/")
        self.client_id = f"{self.origin}/agent.json"
        self.redirect_uri = f"{self.origin}/oauth/callback"
        self.sign_key = generate_p256()
        self.sign_jwk = public_jwk(self.sign_key, "pip-sig-1")
        self.dpop_key = generate_p256()
        self.dpop_jwk = public_jwk(self.dpop_key)
        self.document: dict[str, Any] = {}
        self.metadata: dict[str, Any] = {}
        self.issuer = ""
        self.token_endpoint = ""
        self.revocation_endpoint = ""
        self.authorization_endpoint = ""
        self.conversation_endpoint = ""
        self.session_id = ""
        self.access_token = ""
        self.refresh_token = ""
        self.scope = ""
        self.signed_in = False
        self.conversation_id = ""
        self.cursor = ""
        self.verifier = ""
        self.expected_state = ""
        self.wire: list[dict[str, Any]] = []

    def metadata_document(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_name": "Pip",
            "jwks_uri": f"{self.origin}/jwks.json",
            "redirect_uris": [self.redirect_uri],
            "token_endpoint_auth_method": "private_key_jwt",
        }

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.sign_jwk]}

    def discover(self) -> dict[str, Any]:
        document = self._json("GET", f"{self.company_origin}/.well-known/poppy.json", section="3", title="Fetch poppy.json")
        host = urllib.parse.urlsplit(self.company_origin).hostname or ""
        issuer = document["auth"]["issuer"]
        metadata = self._json("GET", f"{issuer}/.well-known/oauth-authorization-server", section="3.2", title="Fetch OAuth metadata")
        validate_discovery(document, metadata, host)
        self.document = document
        self.metadata = metadata
        self.issuer = metadata["issuer"]
        self.token_endpoint = metadata["token_endpoint"]
        self.revocation_endpoint = metadata["revocation_endpoint"]
        self.authorization_endpoint = metadata["authorization_endpoint"]
        protocols = document.get("agent", {}).get("protocols", [])
        poppy = next(item for item in protocols if item.get("type") == "poppy")
        self.conversation_endpoint = poppy["endpoint"]
        return document

    def open_session(self, *, renew: bool = False) -> dict[str, Any]:
        if not self.token_endpoint:
            self.discover()
        form = {
            "grant_type": JWT,
            "assertion": self._assertion(USER_ID, self.token_endpoint),
            "client_id": self.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._assertion(self.client_id, self.token_endpoint),
        }
        if renew:
            if not self.session_id:
                raise ProtocolError(400, "invalid_session", "there is no session to renew")
            form["session_id"] = self.session_id
        body = self._form(
            "POST",
            self.token_endpoint,
            form,
            section="4.2",
            title="Renew the signed-out session" if renew else "Start a signed-out session",
            bind_token=False,
        )
        self._remember(body)
        return body

    def search(self, query: str) -> dict[str, Any]:
        return self._json(
            "GET",
            f"{self.company_origin}/catalog?q={urllib.parse.quote(query)}",
            section="6",
            title="Search the catalog with the guest session",
            auth=True,
        )

    def read_order(self) -> dict[str, Any]:
        return self._json(
            "GET",
            f"{self.company_origin}/orders/{ORDER_ID}",
            section="6",
            title="Read the order",
            auth=True,
        )

    def exchange(self) -> dict[str, Any]:
        key = "idem_" + secrets.token_urlsafe(12)
        return self._json(
            "POST",
            f"{self.company_origin}/orders/{ORDER_ID}/exchanges",
            {"item_id": "itm_field", "replacement_sku": "field-insulated-m"},
            section="6",
            title="Exchange the jacket",
            auth=True,
            extra_headers={"Idempotency-Key": key},
        )

    def ask(self, text: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        message: dict[str, Any] = {
            "id": "msg_" + secrets.token_urlsafe(12),
            "sender": "agent",
            "text": text,
        }
        if context:
            message["context"] = context
        if self.conversation_id:
            url = f"{self.conversation_endpoint}/{self.conversation_id}/messages?wait=1"
            if self.cursor:
                url += "&cursor=" + urllib.parse.quote(self.cursor)
            title = "Continue the conversation"
        else:
            url = f"{self.conversation_endpoint}?wait=1"
            title = "Ask the company agent"
        body = self._json(
            "POST",
            url,
            {"message": message},
            section="7.3",
            title=title,
            auth=True,
        )
        self.conversation_id = body.get("conversation_id", self.conversation_id)
        if body.get("cursor"):
            self.cursor = body["cursor"]
        return body

    def authorization_url(self, scopes: list[str]) -> str:
        if not self.authorization_endpoint:
            self.discover()
        self.verifier = secrets.token_urlsafe(48)
        self.expected_state = secrets.token_urlsafe(18)
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(scopes),
                "state": self.expected_state,
                "code_challenge": pkce_challenge(self.verifier),
                "code_challenge_method": "S256",
            }
        )
        url = f"{self.authorization_endpoint}?{query}"
        self.wire.append(
            {
                "section": "4.5",
                "title": "Send the user to Cedar Line's page",
                "method": "GET",
                "url": url,
                "status": None,
                "request": {"scope": " ".join(scopes), "code_challenge_method": "S256"},
                "response": {"note": "The browser leaves Pip. The code comes back only after approval."},
            }
        )
        return url

    def grant(self, scopes: list[str], decision: str = "write") -> dict[str, Any]:
        """Stand in for the person submitting Cedar Line's approval form.

        `decision` is `write` (every requested scope), `read` (view only), or `deny`.
        """
        url = self.authorization_url([scope for scope in scopes])
        status, _headers, raw = _http("GET", url, {}, None)
        if status != 200:
            raise ProtocolError(status, "invalid_request", raw.decode("utf-8", "replace"))
        html = raw.decode("utf-8")
        marker = 'name="request_id" value="'
        start = html.find(marker)
        if start < 0:
            raise ProtocolError(500, "server_error", "consent page did not include a request id")
        request_id = html[start + len(marker) : html.find('"', start + len(marker))]
        form = urllib.parse.urlencode({"request_id": request_id, "decision": decision}).encode("utf-8")
        status, headers, _raw = _http(
            "POST",
            self.authorization_endpoint,
            {"Content-Type": "application/x-www-form-urlencoded"},
            form,
            follow=False,
        )
        if status not in (302, 303):
            raise ProtocolError(status, "invalid_request", "approval did not redirect")
        location = headers.get("Location") or headers.get("location") or ""
        params = {key: values[-1] for key, values in urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).items()}
        return self.complete_callback(params)

    def complete_callback(self, params: dict[str, str]) -> dict[str, Any]:
        if params.get("iss") != self.issuer:
            raise ProtocolError(400, "invalid_request", "iss does not match the company")
        if params.get("state") != self.expected_state:
            raise ProtocolError(400, "invalid_request", "state does not match")
        if params.get("error"):
            raise ProtocolError(400, params["error"], "the user did not approve access")
        previous = self.refresh_token
        form = {
            "grant_type": "authorization_code",
            "code": params["code"],
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier,
            "session_id": self.session_id,
            "client_id": self.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._assertion(self.client_id, self.token_endpoint),
        }
        body = self._form(
            "POST",
            self.token_endpoint,
            form,
            section="4.5",
            title="Exchange the code for this same session",
            bind_token=False,
        )
        self._remember(body)
        if body.get("refresh_token"):
            self.refresh_token = body["refresh_token"]
        if previous and previous != self.refresh_token:
            self.revoke_account_token(previous)
        return body

    def open_session_with_account(self, scopes: list[str] | None = None) -> dict[str, Any]:
        if not self.refresh_token:
            raise ProtocolError(400, "invalid_grant", "there is no account token")
        form = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._assertion(self.client_id, self.token_endpoint),
        }
        if scopes is not None:
            form["scope"] = " ".join(scopes)
        body = self._form(
            "POST",
            self.token_endpoint,
            form,
            section="4.8",
            title="Open a new session with the account token",
            bind_token=False,
        )
        self._remember(body)
        self.conversation_id = ""
        self.cursor = ""
        return body

    def revoke_account_token(self, token: str) -> None:
        form = {
            "token": token,
            "token_type_hint": "refresh_token",
            "client_id": self.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self._assertion(self.client_id, self.revocation_endpoint),
        }
        self._form(
            "POST",
            self.revocation_endpoint,
            form,
            section="4.9",
            title="Revoke an account token",
            bind_token=False,
            dpop=False,
            expect_json=False,
        )

    def sign_out(self) -> dict[str, Any]:
        if self.refresh_token:
            self.revoke_account_token(self.refresh_token)
            self.refresh_token = ""
        self.signed_in = False
        self.scope = ""
        return self.open_session(renew=True)

    def company_message(self, events_body: dict[str, Any]) -> dict[str, Any] | None:
        for event in events_body.get("events", []):
            message = event.get("message") or {}
            if message.get("role") == "company":
                return message
        return None

    def _remember(self, body: dict[str, Any]) -> None:
        self.access_token = body.get("access_token", self.access_token)
        self.session_id = body.get("session_id", self.session_id)
        self.scope = body.get("scope", "")
        self.signed_in = bool(body.get("signed_in"))

    def _assertion(self, subject: str, audience: str) -> str:
        now = int(time.time())
        return sign_jwt(
            self.sign_key,
            {
                "iss": self.client_id,
                "sub": subject,
                "aud": audience,
                "iat": now,
                "exp": now + 60,
                "jti": secrets.token_urlsafe(18),
            },
            header={"kid": "pip-sig-1", "typ": "JWT"},
        )

    def _dpop(self, method: str, url: str, access_token: str | None) -> str:
        return dpop_proof(
            self.dpop_key,
            self.dpop_jwk,
            method,
            url,
            access_token=access_token,
            jti=secrets.token_urlsafe(18),
        )

    def _json(
        self,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
        *,
        section: str,
        title: str,
        auth: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        return self._send(
            method,
            url,
            headers,
            payload,
            section=section,
            title=title,
            auth=auth,
            dpop=auth,
            request_view=body,
        )

    def _form(
        self,
        method: str,
        url: str,
        form: dict[str, str],
        *,
        section: str,
        title: str,
        bind_token: bool,
        dpop: bool = True,
        expect_json: bool = True,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        data = urllib.parse.urlencode(form).encode("utf-8")
        return self._send(
            method,
            url,
            headers,
            data,
            section=section,
            title=title,
            auth=False,
            dpop=dpop,
            bind_token=bind_token,
            request_view=_explain_form(form),
            expect_json=expect_json,
        )

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        data: bytes | None,
        *,
        section: str,
        title: str,
        auth: bool,
        dpop: bool = True,
        bind_token: bool = True,
        request_view: Any = None,
        expect_json: bool = True,
    ) -> dict[str, Any]:
        sent = dict(headers)
        if auth:
            sent["Authorization"] = f"DPoP {self.access_token}"
        if dpop:
            bound = self.access_token if auth and bind_token else None
            sent["DPoP"] = self._dpop(method, url, bound)
        status, response_headers, raw = _http(method, url, sent, data)
        parsed = _parse_json(raw) if raw else {}
        public = _redact(parsed if raw else {})
        self.wire.append(
            {
                "section": section,
                "title": title,
                "method": method,
                "url": url.split("?", 1)[0],
                "status": status,
                "request": request_view,
                "response": public,
                "www_authenticate": response_headers.get("WWW-Authenticate") or response_headers.get("www-authenticate"),
            }
        )
        if not expect_json:
            if status >= 400:
                raise ProtocolError(status, "request_failed", raw.decode("utf-8", "replace"))
            return {}
        if status >= 400:
            raise ProtocolError(
                status,
                str(parsed.get("error") or "request_failed"),
                str(parsed.get("error_description") or ""),
                str(parsed.get("scope") or ""),
            )
        return parsed


def _explain_form(form: dict[str, str]) -> dict[str, Any]:
    shown: dict[str, Any] = {}
    secret = {"code", "code_verifier", "refresh_token", "token"}
    claims = {"client_assertion", "assertion"}
    for key, value in form.items():
        if key in secret:
            shown[key] = "redacted"
        elif key in claims and value.count(".") == 2:
            try:
                shown[key] = jwt_claims(value)
            except Exception:
                shown[key] = "redacted"
        else:
            shown[key] = value
    return shown


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        hidden = {"access_token", "refresh_token", "code", "code_verifier"}
        return {key: ("redacted" if key in hidden else _redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _parse_json(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        body = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return {"raw": raw.decode("utf-8", "replace")}
    return body if isinstance(body, dict) else {"value": body}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: Any, headers: Any, newurl: str) -> None:
        return None


def _http(
    method: str,
    url: str,
    headers: dict[str, str],
    data: bytes | None,
    *,
    follow: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, {key: value for key, value in response.headers.items()}, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {key: value for key, value in exc.headers.items()}, exc.read()
