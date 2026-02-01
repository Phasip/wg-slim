import requests


def test_security_headers_present(container_simple):
    """Ensure the server returns important security headers when running in Docker.

    The test hits the root path which is expected to return HTML and checks for
    common security headers that should be present for web applications.
    """
    url = f"{container_simple}/"
    # Follow redirects to reach the actual HTML page the browser would load
    r = requests.get(url, timeout=10, allow_redirects=True)
    assert r.status_code == 200, f"unexpected status {r.status_code}"

    headers = r.headers

    # X-Content-Type-Options must be 'nosniff'
    assert headers.get("X-Content-Type-Options", "").lower() == "nosniff"

    # X-Frame-Options should be present and restrictive (DENY preferred)
    xfo = headers.get("X-Frame-Options", "").upper()
    assert xfo == "DENY", f"Unexpected X-Frame-Options: {xfo}"

    # Referrer-Policy should be 'no-referrer'
    rp = headers.get("Referrer-Policy")
    assert rp == "no-referrer", f"Unexpected Referrer-Policy: {rp}"

    # Content-Security-Policy must contain strict directives we expect
    csp = headers.get("Content-Security-Policy")
    assert csp, "Missing Content-Security-Policy header"
    assert "unsafe" not in csp, f"CSP contains 'unsafe': {csp}"
    # Permissions-Policy should explicitly deny powerful features
    pp = headers.get("Permissions-Policy")
    assert pp, "Missing Permissions-Policy header"

    xpc = headers.get("X-Permitted-Cross-Domain-Policies")
    assert xpc == "none", f"Unexpected X-Permitted-Cross-Domain-Policies: {xpc}"
