#!/usr/bin/env python3
"""Operator-only loopback API transport. Request envelopes and responses may be secrets."""
import json
import ssl
import sys
import urllib.error
import urllib.request

TARGETS = {
    "bao": ("https://localhost:18200", "/srv/fleetory/secrets/openbao/ca.crt"),
    # Recovery requires the OpenBao network namespace; this port is never published.
    "bao-recovery": ("https://localhost:8205", "/srv/fleetory/secrets/openbao/ca.crt"),
    "audit": ("https://localhost:18091", "/srv/fleetory/secrets/immudb/infrastructure-ca"),
    "audit-gateway": ("https://localhost:18090", "/srv/fleetory/secrets/audit-gateway/infrastructure-ca"),
    "keycloak": ("http://127.0.0.1:18080", None),
}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        raise ValueError("Choose one predefined loopback target.")
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("Request envelope is too large.")
    request = json.loads(raw)
    path = request["path"]
    method = request.get("method", "GET")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "#" in path:
        raise ValueError("A relative API path is required.")
    if method not in ("GET", "POST", "PUT", "DELETE"):
        raise ValueError("Unsupported method.")
    origin, ca = TARGETS[sys.argv[1]]
    headers = request.get("headers", {})
    data = None
    if "json" in request:
        data = json.dumps(request["json"], separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif "form" in request:
        from urllib.parse import urlencode
        data = urlencode(request["form"]).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    context = ssl.create_default_context(cafile=ca) if ca else None
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(origin + path, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError("Response is too large.")
        result = {"status": response.status, "body": body.decode("utf-8")}
    # The operator must redirect this response into a protected file.
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.stderr.write("Loopback API request failed; no request or response was logged.\n")
        sys.exit(1)
