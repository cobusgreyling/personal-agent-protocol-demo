"""HTML for Pip's visit and for Cedar Line's approval page."""

from __future__ import annotations

import html
import json


def visit_page(state: dict) -> str:
    payload = json.dumps(state).replace("<", "\\u003c")
    return VISIT_HTML.replace("/*STATE*/", payload)


def consent_page(
    *,
    client_name: str,
    client_id: str,
    request_id: str,
    requested: list[str],
    account_label: str,
    account_email: str,
) -> str:
    read = "poppy:read" in requested
    write = "poppy:write" in requested
    read_button = ""
    write_button = ""
    if read and not write:
        read_button = '<button class="primary" type="submit" name="decision" value="read">Let Pip view the order</button>'
    elif write:
        write_button = '<button class="primary" type="submit" name="decision" value="write">Let Pip make the exchange</button>'
        if read:
            read_button = '<button type="submit" name="decision" value="read">Only let Pip view the order</button>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cedar Line · Approve Pip</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0; min-height: 100vh;
      background: #143027; color: #f4efe4;
      font-family: "Iowan Old Style", Palatino, Georgia, serif;
    }}
    main {{ max-width: 640px; margin: 0 auto; padding: 48px 24px 80px; }}
    .shop {{ letter-spacing: 0.16em; text-transform: uppercase; font-size: 13px; color: #e2b56a; }}
    h1 {{ font-weight: 500; font-size: 40px; line-height: 1.1; margin: 12px 0 8px; }}
    p {{ font-family: "Avenir Next", "Segoe UI", sans-serif; line-height: 1.5; }}
    .card {{
      background: #f4efe4; color: #1b1916;
      border-radius: 18px; padding: 22px; margin: 28px 0;
    }}
    .card h2 {{ font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; margin: 0 0 8px; color: #6d645b; }}
    .who {{ font-size: 28px; margin: 0; }}
    code {{ font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; }}
    form {{ display: flex; flex-direction: column; gap: 10px; }}
    button, .ghost {{
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      font-size: 16px; border-radius: 999px; padding: 12px 18px; cursor: pointer;
    }}
    button {{ border: 1px solid #cfc3b2; background: transparent; color: #1b1916; }}
    button.primary {{ background: #9c4d2b; color: #fff; border-color: #9c4d2b; }}
    .deny {{ background: none; border: none; color: #d7e4dc; text-decoration: underline; cursor: pointer; font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 14px; padding: 0; }}
    .fine {{ color: #d7e4dc; font-size: 14px; }}
  </style>
</head>
<body>
  <main>
    <div class="shop">Cedar Line</div>
    <h1>Pip wants to use your account.</h1>
    <p class="fine">This page is Cedar Line's. Pip is waiting in the other tab of this demo, and it does not see what you do here.</p>
    <div class="card">
      <h2>Account on this page</h2>
      <p class="who">{html.escape(account_label)}</p>
      <p>{html.escape(account_email)}</p>
      <h2>Personal agent</h2>
      <p class="who">{html.escape(client_name)}</p>
      <p>Trust the address, not the name Pip chose.</p>
      <p><code>{html.escape(client_id)}</code></p>
      <h2>What an exchange needs</h2>
      <p><code>poppy:read</code> views order CL-1042. <code>poppy:write</code> changes it. View access does not include the change.</p>
      <form method="post" action="/oauth/authorize">
        <input type="hidden" name="request_id" value="{html.escape(request_id)}">
        {write_button}
        {read_button}
      </form>
    </div>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="request_id" value="{html.escape(request_id)}">
      <button class="deny" type="submit" name="decision" value="deny">Decline</button>
    </form>
  </main>
</body>
</html>
"""


VISIT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>See Poppy · Pip and Cedar Line</title>
  <style>
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      margin: 0; background: #f3ecdf; color: #1b1916;
      font-family: "Iowan Old Style", Palatino, Georgia, serif;
    }
    header, main { max-width: 1100px; margin: 0 auto; padding: 28px 22px; }
    header { padding-bottom: 0; }
    .kicker { letter-spacing: 0.16em; text-transform: uppercase; font-size: 12px; color: #9c4d2b; font-family: "Avenir Next", "Segoe UI", sans-serif; }
    h1 { font-weight: 500; font-size: 46px; line-height: 1.05; margin: 8px 0; overflow-wrap: break-word; }
    .lede { max-width: 640px; font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 17px; line-height: 1.45; }
    ol.steps { display: flex; gap: 8px; flex-wrap: wrap; list-style: none; padding: 0; margin: 22px 0 0; }
    ol.steps li {
      font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 13px;
      border: 1px solid #e2d5c3; border-radius: 999px; padding: 6px 10px; color: #6d645b;
    }
    ol.steps li.done { background: #1b1916; color: #f3ecdf; border-color: #1b1916; }
    .layout { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.85fr); gap: 18px; align-items: start; }
    .line { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 10px; padding: 10px 0; border-top: 1px solid #f0e6d8; }
    @media (max-width: 860px) {
      .layout { grid-template-columns: minmax(0, 1fr); }
      h1 { font-size: 32px; }
      .line { grid-template-columns: 64px minmax(0, 1fr); }
    }
    section { background: #fffaf3; border: 1px solid #e2d5c3; border-radius: 18px; padding: 18px; }
    h2 { font-size: 22px; font-weight: 500; margin: 0 0 12px; }

    .who { font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: #9c4d2b; padding-top: 4px; }
    .who.you { color: #1b1916; }
    .who.cedar { color: #1e3a2f; }
    button {
      font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 16px;
      background: #9c4d2b; color: white; border: 0; border-radius: 999px;
      padding: 12px 18px; cursor: pointer; margin-top: 12px;
    }
    button.quiet { background: transparent; color: #1b1916; border: 1px solid #cfc3b2; }
    button:disabled { opacity: 0.6; cursor: wait; }
    .ticket { background: #1e3a2f; color: #f4efe4; border-radius: 14px; padding: 14px; margin-bottom: 12px; }
    .ticket span { display: block; font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: #e2b56a; }
    .ticket strong { font-size: 22px; font-weight: 500; }
    .fact { font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 14px; line-height: 1.4; margin: 6px 0; }
    .fact b { font-weight: 600; }
    .wire { font-family: ui-monospace, monospace; font-size: 12px; }
    details { border-top: 1px solid #f0e6d8; padding: 8px 0; }
    summary { cursor: pointer; }
    pre { white-space: pre-wrap; word-break: break-word; background: #1b1916; color: #f3ecdf; padding: 10px; border-radius: 10px; }
    .status { color: #9c4d2b; }
    footer { max-width: 1100px; margin: 0 auto; padding: 8px 22px 40px; font-family: "Avenir Next", "Segoe UI", sans-serif; font-size: 13px; color: #6d645b; }
  </style>
</head>
<body>
  <header>
    <div class="kicker">Personal Agent Protocol · draft 0.1</div>
    <h1>See the visit from both sides.</h1>
    <p class="lede">Pip is your agent. Cedar Line is the shop. You approve access on Cedar Line's own page. Every line in the log is a real request from this process.</p>
    <ol class="steps" id="steps"></ol>
  </header>
  <main class="layout">
    <section>
      <h2>You and Pip</h2>
      <div id="chat"></div>
      <div id="actions"></div>
    </section>
    <div>
      <section>
        <h2>What Cedar Line knows</h2>
        <div id="company"></div>
      </section>
      <section style="margin-top:18px">
        <h2>The wire</h2>
        <div class="wire" id="wire"></div>
      </section>
    </div>
  </main>
  <footer>Local stand-in for HTTPS: this process uses <code>http://127.0.0.1</code>. Account tokens are kept in memory and redacted in the log. Cedar Line and Alex Mora are fictional.</footer>
  <script id="state" type="application/json">/*STATE*/</script>
  <noscript>This page needs JavaScript to call Pip. The same visit can be printed with <code>python3 demo.py --visit</code>.</noscript>
  <script>
    const state = JSON.parse(document.getElementById("state").textContent);
    const steps = document.getElementById("steps");
    const chat = document.getElementById("chat");
    const actions = document.getElementById("actions");
    const company = document.getElementById("company");
    const wire = document.getElementById("wire");

    state.steps.forEach((step) => {
      const item = document.createElement("li");
      item.textContent = step.label;
      if (step.done) item.className = "done";
      steps.appendChild(item);
    });

    if (!state.chat.length) {
      const line = document.createElement("div");
      line.className = "line";
      line.innerHTML = '<div class="who you">You</div><div>My Field jacket keeps the rain out, but it is not warm enough. Can you exchange it?</div>';
      chat.appendChild(line);
    }
    state.chat.forEach((entry) => {
      const line = document.createElement("div");
      line.className = "line";
      const who = document.createElement("div");
      who.className = "who " + entry.who;
      who.textContent = entry.who === "you" ? "You" : entry.who === "pip" ? "Pip" : "Cedar Line";
      const text = document.createElement("div");
      text.textContent = entry.text;
      line.append(who, text);
      chat.appendChild(line);
    });

    const button = document.createElement("button");
    if (state.phase === "ready") {
      button.textContent = "Ask Pip";
      button.onclick = () => post("/demo/ask", button);
    } else if (state.phase === "asked" || state.phase === "needs_write" || state.phase === "declined") {
      button.textContent = state.phase === "needs_write" ? "Approve the change on Cedar Line's page" : "Continue on Cedar Line's page";
      button.onclick = async () => {
        button.disabled = true;
        const response = await fetch("/demo/authorize", {method: "POST"});
        const body = await response.json();
        window.location = body.url;
      };
    } else if (state.phase === "exchanged") {
      button.textContent = "Disconnect Pip";
      button.onclick = () => post("/demo/sign-out", button);
    } else {
      button.className = "quiet";
      button.textContent = "Restart python3 demo.py for a fresh order";
      button.disabled = true;
    }
    actions.appendChild(button);

    const order = state.ledger.order || {};
    const ticket = document.createElement("div");
    ticket.className = "ticket";
    const label = document.createElement("span");
    label.textContent = "Order " + (order.id || "");
    const name = document.createElement("strong");
    name.textContent = order.name || "Field jacket";
    const detail = document.createElement("div");
    detail.className = "fact";
    detail.textContent = (order.size || "medium") + " · " + (order.status || "delivered");
    ticket.append(label, name, detail);
    company.appendChild(ticket);

    const sessions = state.ledger.sessions || [];
    if (!sessions.length) {
      addFact(company, "No session yet. Pip has not contacted Cedar Line.");
    }
    sessions.forEach((session) => {
      addFact(company, "Agent", session.client_name);
      addFact(company, "Client", session.client_id);
      addFact(company, "User id", session.user_id + "  ·  not an email, and different at every company");
      addFact(company, "Session", session.session_id);
      addFact(company, "Signed in", session.signed_in ? session.account : "No");
      addFact(company, "Access", session.scopes.length ? session.scopes.join(" ") : "guest");
    });

    if (!state.wire.length) {
      addFact(wire, "The requests will show up here.");
    }
    state.wire.forEach((entry, index) => {
      const details = document.createElement("details");
      if (index === state.wire.length - 1) details.open = true;
      const summary = document.createElement("summary");
      const status = entry.status == null ? "" : "  " + entry.status;
      summary.textContent = entry.section + "  " + entry.method + "  " + entry.title + status;
      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify({request: entry.request, response: entry.response, www_authenticate: entry.www_authenticate}, null, 2);
      details.append(summary, pre);
      wire.appendChild(details);
    });

    function addFact(parent, label, value) {
      const row = document.createElement("div");
      row.className = "fact";
      if (value === undefined) row.textContent = label;
      else {
        const name = document.createElement("b");
        name.textContent = label + "  ";
        row.append(name, document.createTextNode(value));
      }
      parent.appendChild(row);
    }

    async function post(path, control) {
      control.disabled = true;
      control.textContent = "Working…";
      const response = await fetch(path, {method: "POST"});
      if (!response.ok) {
        control.disabled = false;
        control.textContent = "Something failed. See the terminal.";
        return;
      }
      window.location.reload();
    }
  </script>
</body>
</html>
"""
