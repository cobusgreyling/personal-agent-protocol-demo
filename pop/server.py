"""The browser for the visit. Pip's pages live here. Cedar Line lives next door."""

from __future__ import annotations

import json
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pop.agent import USER_ID, PersonalAgent, ProtocolError
from pop.company import serve_company
from pop.pages import visit_page


class Visit:
    def __init__(self, company_origin: str, own_origin: str) -> None:
        self.agent = PersonalAgent(company_origin, own_origin)
        self.phase = "ready"
        self.chat: list[dict[str, str]] = []

    def ask(self) -> None:
        if self.phase != "ready":
            return
        document = self.agent.discover()
        self.agent.open_session()
        catalog = self.agent.search("warmer")
        events = self.agent.ask(
            "The Field jacket from order CL-1042 is not warm enough. The user wants a warmer exchange.",
            {"locale": "en-US", "time_zone": "America/Los_Angeles", "user_available": True},
        )
        company = self.agent.company_message(events) or {}
        insulated = next(item for item in catalog["products"] if item["sku"] == "field-insulated-m")
        self.chat = [
            {
                "who": "you",
                "text": "My Field jacket keeps the rain out, but it isn't warm enough. Can you exchange it?",
            },
            {
                "who": "pip",
                "text": (
                    f"Cedar Line publishes Poppy {document['protocol_version']}. "
                    f"I opened a guest session. Their id for you here is {USER_ID}. That is not an email address."
                ),
            },
            {
                "who": "pip",
                "text": (
                    f"Their catalog lists the insulated field jacket at ${insulated['price_usd']}. "
                    "That is $48 more than the Field jacket."
                ),
            },
            {"who": "cedar", "text": company.get("text", "")},
            {
                "who": "pip",
                "text": "Changing the order needs your account. You approve that on Cedar Line's page. I do not see the password.",
            },
        ]
        self.phase = "asked"

    def authorization_url(self) -> str:
        return self.agent.authorization_url(["poppy:read", "poppy:write"])

    def finish(self, params: dict[str, str]) -> None:
        try:
            self.agent.complete_callback(params)
        except ProtocolError as exc:
            if exc.error == "access_denied":
                self.phase = "declined"
                self.chat.append(
                    {
                        "who": "pip",
                        "text": "You declined on Cedar Line's page. I still only have the guest session, so I cannot see the order.",
                    }
                )
                return
            raise
        try:
            result = self.agent.exchange()
        except ProtocolError as exc:
            if exc.error != "insufficient_scope":
                raise
            order = self.agent.read_order()
            self.phase = "needs_write"
            self.chat.append(
                {
                    "who": "pip",
                    "text": (
                        f"Cedar Line let me view {order['id']}, the {order['name']}. "
                        "They refused the exchange. View access does not include changes."
                    ),
                }
            )
            return
        order = result["order"]
        self.phase = "exchanged"
        self.chat.append(
            {
                "who": "pip",
                "text": (
                    f"Cedar Line exchanged {order['id']} for the {order['name']}. "
                    f"The guest question and the change are the same session, {self.agent.session_id}."
                ),
            }
        )
        confirmed = self.agent.ask("The exchange is done. Please confirm order CL-1042.")
        message = self.agent.company_message(confirmed) or {}
        if message.get("text"):
            self.chat.append({"who": "cedar", "text": message["text"]})

    def sign_out(self) -> None:
        self.agent.sign_out()
        self.phase = "signed_out"
        self.chat.append(
            {
                "who": "pip",
                "text": (
                    "I revoked the account token. The session is still there, signed out. "
                    "I can search the catalog. I can no longer open the order."
                ),
            }
        )

    def state(self) -> dict[str, Any]:
        ledger = self._ledger()
        return {
            "phase": self.phase,
            "chat": self.chat,
            "wire": self.agent.wire,
            "ledger": ledger,
            "steps": self._steps(),
        }

    def _steps(self) -> list[dict[str, Any]]:
        sections = {entry["section"] for entry in self.agent.wire}
        return [
            {"label": "Discover", "done": "3" in sections or "3.2" in sections},
            {"label": "Guest session", "done": bool(self.agent.session_id)},
            {"label": "Ask", "done": bool(self.agent.conversation_id)},
            {"label": "Your approval", "done": self.phase in {"needs_write", "exchanged", "signed_out"}},
            {"label": "Exchange", "done": self.phase in {"exchanged", "signed_out"}},
        ]

    def _ledger(self) -> dict[str, Any]:
        from pop.agent import _http, _parse_json

        status, _headers, raw = _http("GET", f"{self.agent.company_origin}/demo/ledger", {}, None)
        if status != 200:
            return {"sessions": [], "order": {}}
        return _parse_json(raw)


class VisitServer(ThreadingHTTPServer):
    visit: Visit

    def __init__(self, port: int) -> None:
        super().__init__(("127.0.0.1", port), VisitHandler)


class VisitHandler(BaseHTTPRequestHandler):
    server: VisitServer

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    @property
    def visit(self) -> Visit:
        return self.server.visit

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._html(visit_page(self.visit.state()))
        elif path == "/agent.json":
            self._json(self.visit.agent.metadata_document())
        elif path == "/jwks.json":
            self._json(self.visit.agent.jwks())
        elif path == "/oauth/callback":
            self._callback()
        elif path == "/demo/state":
            self._json(self.visit.state())
        else:
            self._json({"error": "not_found"}, status=404)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/demo/ask":
                self.visit.ask()
                self._json(self.visit.state())
            elif path == "/demo/authorize":
                self._json({"url": self.visit.authorization_url()})
            elif path == "/demo/sign-out":
                self.visit.sign_out()
                self._json(self.visit.state())
            else:
                self._json({"error": "not_found"}, status=404)
        except Exception:
            traceback.print_exc()
            self._json({"error": "server_error"}, status=500)

    def _callback(self) -> None:
        query = urllib.parse.urlsplit(self.path).query
        params = {key: values[-1] for key, values in urllib.parse.parse_qs(query).items()}
        try:
            self.visit.finish(params)
        except Exception:
            traceback.print_exc()
            self._html("<h1>Pip could not finish sign-in.</h1><p>The terminal has the reason.</p>", status=500)
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _html(self, page: str, status: int = 200) -> None:
        raw = page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, body: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve_visit(port: int = 0) -> tuple[Visit, Any, VisitServer]:
    _company, company_httpd, _thread = serve_company(0)
    visit_httpd = VisitServer(port)
    origin = f"http://127.0.0.1:{visit_httpd.server_address[1]}"
    visit_httpd.visit = Visit(company_httpd.company.origin, origin)
    thread = threading.Thread(target=visit_httpd.serve_forever, name="pip", daemon=True)
    thread.start()
    return visit_httpd.visit, company_httpd, visit_httpd
