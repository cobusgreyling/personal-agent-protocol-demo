"""The visit Cedar Line and Pip actually run."""

from __future__ import annotations

import json
import unittest
import urllib.parse

from pop.agent import USER_ID, DiscoveryError, ProtocolError, _http, validate_discovery
from pop.company import ORDER_ID
from pop.jose import CLIENT_ASSERTION_TYPE, JWT
from pop.server import serve_visit


class DiscoveryChecks(unittest.TestCase):
    def test_foreign_issuer_is_refused(self) -> None:
        document = {
            "protocol_version": "0.1",
            "organization": {"name": "Cedar Line", "domain": "127.0.0.1"},
            "auth": {"issuer": "http://127.0.0.1:9"},
        }
        metadata = {
            "issuer": "http://127.0.0.1:9",
            "token_endpoint": "http://127.0.0.1:9/oauth/token",
            "revocation_endpoint": "http://127.0.0.1:9/oauth/revoke",
            "authorization_endpoint": "http://127.0.0.1:9/oauth/authorize",
            "poppy_domains": ["other.example"],
        }
        with self.assertRaises(DiscoveryError):
            validate_discovery(document, metadata, "127.0.0.1")

    def test_major_version_must_be_supported(self) -> None:
        document = {
            "protocol_version": "1.0",
            "organization": {"domain": "127.0.0.1"},
            "auth": {"issuer": "http://127.0.0.1:9"},
        }
        metadata = {
            "issuer": "http://127.0.0.1:9",
            "token_endpoint": "x",
            "revocation_endpoint": "x",
            "authorization_endpoint": "x",
            "poppy_domains": ["127.0.0.1"],
        }
        with self.assertRaises(DiscoveryError):
            validate_discovery(document, metadata, "127.0.0.1")


class VisitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.visit, self.company_httpd, self.visit_httpd = serve_visit(0)
        self.agent = self.visit.agent

    def tearDown(self) -> None:
        self.visit_httpd.shutdown()
        self.company_httpd.shutdown()
        self.visit_httpd.server_close()
        self.company_httpd.server_close()

    def test_write_grant_keeps_the_guest_session(self) -> None:
        self.agent.discover()
        self.agent.open_session()
        session = self.agent.session_id
        catalog = self.agent.search("warmer")
        self.assertIn("field-insulated-m", [item["sku"] for item in catalog["products"]])
        with self.assertRaises(ProtocolError) as guest:
            self.agent.exchange()
        self.assertEqual(guest.exception.error, "sign_in_required")
        events = self.agent.ask("The jacket is not warm enough.")
        self.assertEqual(self.agent.company_message(events)["sender"], "agent")
        self.agent.grant(["poppy:read", "poppy:write"], decision="write")
        self.assertEqual(self.agent.session_id, session)
        self.assertTrue(self.agent.signed_in)
        self.assertEqual(self.agent.scope, "poppy:read poppy:write")
        result = self.agent.exchange()
        self.assertEqual(result["order"]["name"], "Insulated field jacket")
        self.assertEqual(result["price_difference_usd"], 48)
        again = self.agent.exchange()
        self.assertFalse(again["changed"])
        dumped = json.dumps(self.agent.wire)
        self.assertNotIn(self.agent.access_token, dumped)
        self.assertNotIn(self.agent.refresh_token, dumped)

    def test_read_grant_can_view_and_cannot_change(self) -> None:
        self.agent.discover()
        self.agent.open_session()
        self.agent.grant(["poppy:read", "poppy:write"], decision="read")
        self.assertEqual(self.agent.scope, "poppy:read")
        order = self.agent.read_order()
        self.assertEqual(order["id"], ORDER_ID)
        self.assertEqual(order["name"], "Field jacket")
        with self.assertRaises(ProtocolError) as refused:
            self.agent.exchange()
        self.assertEqual(refused.exception.error, "insufficient_scope")
        self.assertEqual(refused.exception.scope, "poppy:write")
        self.assertIn('error="insufficient_scope"', self.agent.wire[-1]["www_authenticate"])
        self.assertEqual(self.agent.read_order()["name"], "Field jacket")

    def test_account_token_opens_a_signed_in_session_then_sign_out(self) -> None:
        self.agent.discover()
        self.agent.open_session()
        first = self.agent.session_id
        self.agent.grant(["poppy:read", "poppy:write"], decision="write")
        self.agent.open_session_with_account(["poppy:read"])
        self.assertNotEqual(self.agent.session_id, first)
        self.assertEqual(self.agent.scope, "poppy:read")
        self.assertEqual(self.agent.read_order()["id"], ORDER_ID)
        with self.assertRaises(ProtocolError) as refused:
            self.agent.exchange()
        self.assertEqual(refused.exception.error, "insufficient_scope")
        current = self.agent.session_id
        self.agent.sign_out()
        self.assertFalse(self.agent.signed_in)
        self.assertEqual(self.agent.session_id, current)
        catalog = self.agent.search("jacket")
        self.assertGreaterEqual(len(catalog["products"]), 1)
        with self.assertRaises(ProtocolError) as signed_out:
            self.agent.read_order()
        self.assertEqual(signed_out.exception.error, "sign_in_required")

    def test_message_retry_and_conflict(self) -> None:
        self.agent.discover()
        self.agent.open_session()
        url = f"{self.agent.conversation_endpoint}?wait=1"
        message = {"id": "msg_sameid0000001", "sender": "agent", "text": "Is a warmer jacket available?"}
        first = self.agent._json("POST", url, {"message": message}, section="7.3", title="first", auth=True)
        second = self.agent._json("POST", url, {"message": message}, section="7.3", title="retry", auth=True)
        self.assertEqual(first["conversation_id"], second["conversation_id"])
        changed = {"id": message["id"], "sender": "agent", "text": "A different question."}
        with self.assertRaises(ProtocolError) as conflict:
            self.agent._json("POST", url, {"message": changed}, section="7.3", title="conflict", auth=True)
        self.assertEqual(conflict.exception.error, "message_id_conflict")

    def test_replayed_dpop_proof_is_rejected(self) -> None:
        self.agent.discover()
        proof = self.agent._dpop("POST", self.agent.token_endpoint, None)

        def post() -> tuple[int, dict]:
            form = {
                "grant_type": JWT,
                "assertion": self.agent._assertion(USER_ID, self.agent.token_endpoint),
                "client_id": self.agent.client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": self.agent._assertion(self.agent.client_id, self.agent.token_endpoint),
            }
            status, _headers, raw = _http(
                "POST",
                self.agent.token_endpoint,
                {"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof},
                urllib.parse.urlencode(form).encode("utf-8"),
            )
            return status, json.loads(raw.decode("utf-8"))

        first_status, first_body = post()
        self.assertEqual(first_status, 200)
        self.assertFalse(first_body["signed_in"])
        second_status, second_body = post()
        self.assertEqual(second_status, 400)
        self.assertEqual(second_body["error"], "invalid_dpop_proof")

    def test_decline_leaves_the_guest_session(self) -> None:
        self.agent.discover()
        self.agent.open_session()
        with self.assertRaises(ProtocolError) as declined:
            self.agent.grant(["poppy:read", "poppy:write"], decision="deny")
        self.assertEqual(declined.exception.error, "access_denied")
        self.assertFalse(self.agent.signed_in)
        self.assertTrue(self.agent.search("jacket")["products"])

    def test_pages_follow_the_approval(self) -> None:
        origin = self.agent.origin
        status, _headers, page = _http("GET", origin + "/", {}, None)
        self.assertEqual(status, 200)
        self.assertIn(b"Ask Pip", page)
        status, _headers, raw = _http("POST", origin + "/demo/ask", {}, b"")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["phase"], "asked")
        status, _headers, page = _http("GET", origin + "/", {}, None)
        self.assertIn(b"Continue on Cedar Line", page)
        status, _headers, raw = _http("POST", origin + "/demo/authorize", {}, b"")
        url = json.loads(raw)["url"]
        status, _headers, consent = _http("GET", url, {}, None)
        self.assertIn(b"Let Pip make the exchange", consent)
        marker = 'name="request_id" value="'
        request_id = consent.decode("utf-8").split(marker, 1)[1].split('"', 1)[0]
        status, headers, _raw = _http(
            "POST",
            self.agent.authorization_endpoint,
            {"Content-Type": "application/x-www-form-urlencoded"},
            urllib.parse.urlencode({"request_id": request_id, "decision": "write"}).encode("utf-8"),
            follow=False,
        )
        location = headers.get("Location") or headers.get("location")
        status, headers, _raw = _http("GET", location, {}, None, follow=False)
        self.assertEqual(status, 303)
        status, _headers, page = _http("GET", origin + "/", {}, None)
        self.assertIn(b"Disconnect Pip", page)
        self.assertIn(b"Insulated field jacket", page)

    def test_browser_finish_records_a_read_refusal(self) -> None:
        self.visit.ask()
        url = self.agent.authorization_url(["poppy:read", "poppy:write"])
        status, _headers, raw = _http("GET", url, {}, None)
        self.assertEqual(status, 200)
        html = raw.decode("utf-8")
        marker = 'name="request_id" value="'
        request_id = html.split(marker, 1)[1].split('"', 1)[0]
        status, headers, _raw = _http(
            "POST",
            self.agent.authorization_endpoint,
            {"Content-Type": "application/x-www-form-urlencoded"},
            urllib.parse.urlencode({"request_id": request_id, "decision": "read"}).encode("utf-8"),
            follow=False,
        )
        self.assertIn(status, (302, 303))
        location = headers.get("Location") or headers.get("location")
        params = {key: values[-1] for key, values in urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).items()}
        self.visit.finish(params)
        self.assertEqual(self.visit.phase, "needs_write")
        self.assertIn("does not include changes", self.visit.chat[-1]["text"])


if __name__ == "__main__":
    unittest.main()
