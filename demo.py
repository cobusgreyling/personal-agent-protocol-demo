#!/usr/bin/env python3
"""Open the Poppy visit, or print one in the terminal."""

from __future__ import annotations

import sys
import time
import webbrowser


def main(argv: list[str]) -> int:
    from pop.server import serve_visit

    company_httpd = None
    visit_httpd = None
    try:
        visit, company_httpd, visit_httpd = serve_visit(0)
        if "--visit" in argv:
            decision = "read" if "read" in argv else "write"
            return run_visit(visit, decision)
        url = visit.agent.origin + "/"
        print(f"Pip is at {url}")
        print("Cedar Line is the other port in this process. Stop with Ctrl+C.")
        webbrowser.open(url)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0
    finally:
        for httpd in (visit_httpd, company_httpd):
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
    return 0


def run_visit(visit, decision: str) -> int:
    from pop.agent import USER_ID, ProtocolError

    visit.ask()
    session = visit.agent.session_id
    print(f"Discovered Cedar Line, Poppy {visit.agent.document['protocol_version']}.")
    print(f"Guest session {session}. User id {USER_ID}.")
    cedar = next(line["text"] for line in visit.chat if line["who"] == "cedar")
    print(f"Cedar Line's agent: {cedar}")
    try:
        visit.agent.grant(["poppy:read", "poppy:write"], decision=decision)
    except ProtocolError as exc:
        print(f"Sign-in ended with {exc.error}.")
        return 1
    print(f"Same session {visit.agent.session_id}. signed_in={visit.agent.signed_in}. scope={visit.agent.scope!r}.")
    if visit.agent.session_id != session:
        print("Session changed. Direct sign-in should keep it.")
        return 1
    try:
        result = visit.agent.exchange()
    except ProtocolError as exc:
        if decision == "read" and exc.error == "insufficient_scope":
            order = visit.agent.read_order()
            print(f"View can see {order['id']}, the {order['name']}.")
            print(f"The exchange was refused: {exc.error} scope={exc.scope}.")
            return 0
        print(f"Exchange failed: {exc.error} {exc.description}")
        return 1
    order = result["order"]
    print(f"Exchanged {order['id']} for the {order['name']}. Difference ${result['price_difference_usd']}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ModuleNotFoundError as exc:
        if exc.name == "cryptography":
            print("Install the one dependency first: python3 -m pip install -r requirements.txt", file=sys.stderr)
            raise SystemExit(1) from exc
        raise
