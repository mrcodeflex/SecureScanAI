"""Rule knowledge base for the built-in website checks.

Each rule carries plain-language text (Beginner mode) and technical remediation
(Advanced mode). finding_type values:
  vulnerability    - verified by an engine (for example a CVE matched to an exact version)
  misconfiguration - an observed weakness in the target's configuration
  missing_control  - a recommended security control is absent (not proof of exploitability)
  potential        - heuristic match that needs human review
  observation      - informational only
"""
from __future__ import annotations

# rule_id: (title, severity, category, finding_type, cwe, simple, why, fix)
WEB_RULES: dict[str, tuple] = {
    "WEB-HTTPS-001": (
        "Website is served over unencrypted HTTP", "medium", "Transport security", "misconfiguration",
        "CWE-319",
        "The site loads over plain HTTP, so anything sent between visitors and the site can be read or changed on the way.",
        "Passwords, session cookies and personal data can be intercepted on shared or hostile networks.",
        "Install a TLS certificate (for example from Let's Encrypt), serve the whole site over HTTPS and redirect HTTP to HTTPS."),
    "WEB-HTTPS-002": (
        "HTTP version of the site does not redirect to HTTPS", "medium", "Transport security",
        "misconfiguration", "CWE-319",
        "Visitors who type the address without https:// stay on the unencrypted version of the site.",
        "An attacker on the network can read or tamper with traffic from those visitors.",
        "Redirect all http:// requests to https:// with a permanent (301/308) redirect, then enable HSTS."),
    "WEB-TLS-001": (
        "TLS certificate could not be validated", "high", "Transport security", "misconfiguration",
        "CWE-295",
        "Browsers cannot confirm this site's HTTPS certificate is valid, so visitors see warnings or are exposed to impersonation.",
        "Invalid, expired or mismatched certificates break trust and teach users to ignore warnings.",
        "Install a valid certificate from a trusted CA that matches the host name, includes the full chain and is not expired."),
    "WEB-TLS-002": (
        "TLS certificate expires soon", "medium", "Transport security", "misconfiguration", "CWE-298",
        "The site's HTTPS certificate will expire in a few weeks.",
        "When it expires, browsers will block visitors with a security warning.",
        "Renew the certificate and automate renewal (for example with ACME/certbot)."),
    "WEB-TLS-010": (
        "TLS connection details", "info", "Transport security", "observation", None,
        "Details about the encrypted connection to the site.",
        "Useful for audits and for confirming the certificate and protocol in use.",
        "No action required."),
    "WEB-HDR-001": (
        "Content-Security-Policy header is missing", "medium", "Security headers", "missing_control",
        "CWE-693",
        "The site does not tell browsers which scripts and resources it trusts.",
        "A Content-Security-Policy is a strong second line of defence that limits the damage of script-injection (XSS) bugs.",
        "Add a Content-Security-Policy header, starting with a restrictive policy such as default-src 'self' and loosening only what is needed."),
    "WEB-HDR-002": (
        "Content-Security-Policy allows unsafe sources", "low", "Security headers", "misconfiguration",
        "CWE-693",
        "The site has a content policy, but it allows risky script sources such as inline or wildcard scripts.",
        "Permissive directives remove most of the protection a CSP is meant to provide.",
        "Remove 'unsafe-inline', 'unsafe-eval' and wildcards from script-src; use nonces or hashes instead."),
    "WEB-HDR-003": (
        "Strict-Transport-Security (HSTS) header is missing", "medium", "Security headers",
        "missing_control", "CWE-319",
        "The site does not tell browsers to always use HTTPS.",
        "Without HSTS, a first visit over HTTP can be downgraded or intercepted.",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere."),
    "WEB-HDR-004": (
        "Strict-Transport-Security max-age is too short", "low", "Security headers", "misconfiguration",
        "CWE-319",
        "The HTTPS-only instruction given to browsers expires too quickly.",
        "A short HSTS lifetime leaves visitors unprotected after it lapses.",
        "Use a max-age of at least 15552000 seconds (180 days); 31536000 is recommended."),
    "WEB-HDR-005": (
        "X-Content-Type-Options header is missing", "low", "Security headers", "missing_control",
        "CWE-693",
        "Browsers may guess file types instead of trusting the server.",
        "Type guessing can turn an uploaded file into executable script in some situations.",
        "Send X-Content-Type-Options: nosniff on all responses."),
    "WEB-HDR-006": (
        "No clickjacking protection (X-Frame-Options / frame-ancestors)", "medium", "Security headers",
        "missing_control", "CWE-1021",
        "Other websites can load this site inside a hidden frame.",
        "Attackers can trick visitors into clicking buttons on your site without realising it (clickjacking).",
        "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN)."),
    "WEB-HDR-007": (
        "Referrer-Policy header is missing", "low", "Security headers", "missing_control", "CWE-200",
        "The site does not control how much of its address is shared with other sites.",
        "Full URLs, which may contain tokens or private paths, can leak to third parties.",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
    "WEB-HDR-008": (
        "Permissions-Policy header is missing", "info", "Security headers", "missing_control", "CWE-693",
        "The site does not restrict browser features such as camera, microphone and location.",
        "Restricting unused features reduces what a compromised script could do.",
        "Send a Permissions-Policy header that disables features you do not use."),
    "WEB-DISC-001": (
        "Server header discloses software version", "low", "Information disclosure",
        "misconfiguration", "CWE-200",
        "The server announces exactly which software and version it runs.",
        "Attackers use this to look up known weaknesses for that version.",
        "Remove version details from the Server header (for example ServerTokens Prod in Apache, server_tokens off in nginx)."),
    "WEB-DISC-002": (
        "Technology disclosed in response headers", "low", "Information disclosure",
        "misconfiguration", "CWE-200",
        "Response headers reveal the programming platform used by the site.",
        "This helps attackers pick targeted exploits.",
        "Remove headers such as X-Powered-By and X-AspNet-Version in the server or framework configuration."),
    "WEB-TECH-001": (
        "Detected technologies", "info", "Information disclosure", "observation", None,
        "Technologies that can be identified from the site's responses.",
        "Knowing what is exposed helps you decide what to hide or keep patched.",
        "Keep identified components patched; hide version details where possible."),
    "WEB-COOKIE-001": (
        "Cookie is missing the Secure flag", "medium", "Cookies", "misconfiguration", "CWE-614",
        "A cookie can be sent over unencrypted connections.",
        "On a hostile network the cookie (possibly a login session) can be stolen.",
        "Set the Secure attribute on every cookie that is served over HTTPS."),
    "WEB-COOKIE-002": (
        "Cookie is missing the HttpOnly flag", "medium", "Cookies", "misconfiguration", "CWE-1004",
        "Scripts running in the page can read this cookie.",
        "If an attacker injects a script, they can steal the cookie and take over the session.",
        "Set the HttpOnly attribute on session and authentication cookies."),
    "WEB-COOKIE-003": (
        "Cookie is missing the SameSite attribute", "low", "Cookies", "misconfiguration", "CWE-1275",
        "The cookie does not say whether other sites may trigger requests that include it.",
        "This can make cross-site request forgery (CSRF) easier.",
        "Set SameSite=Lax (or Strict) unless cross-site use is genuinely required."),
    "WEB-COOKIE-004": (
        "Cookie uses SameSite=None without Secure", "medium", "Cookies", "misconfiguration", "CWE-1275",
        "The cookie is allowed in cross-site requests but is not restricted to HTTPS.",
        "Browsers reject this combination and it exposes the cookie to interception.",
        "Add the Secure attribute whenever SameSite=None is used."),
    "WEB-REDIR-001": (
        "HTTPS request is redirected to HTTP", "high", "Transport security", "misconfiguration",
        "CWE-319",
        "A secure address sends visitors to an insecure one.",
        "Visitors lose encryption part-way through their visit.",
        "Fix the redirect so it never leaves HTTPS."),
    "WEB-REDIR-002": (
        "Redirect to a different domain", "info", "Redirects", "observation", None,
        "The address sends visitors to another website domain.",
        "Usually expected (for example example.com to www.example.com), but worth confirming.",
        "Confirm the destination is intended."),
    "WEB-REDIR-003": (
        "Long redirect chain", "low", "Redirects", "misconfiguration", "CWE-601",
        "Visitors are bounced through many redirects before reaching the page.",
        "Long chains slow the site and make security behaviour harder to reason about.",
        "Redirect directly to the final address."),
    "WEB-ERR-001": (
        "Server error details exposed to visitors", "medium", "Information disclosure",
        "misconfiguration", "CWE-209",
        "The site shows technical error messages or stack traces.",
        "Error details reveal file paths, framework versions and query structure that help attackers.",
        "Disable debug output in production and show a generic error page; log details server-side."),
    "WEB-ERR-002": (
        "Server returned an error status", "low", "Availability", "observation", None,
        "The page returned a server error (5xx) when it was requested.",
        "The site may be unstable or misconfigured, which can also hide other issues.",
        "Check the server logs for the cause."),
    "WEB-FORM-001": (
        "Password field on a page served over HTTP", "high", "Forms", "misconfiguration", "CWE-319",
        "A login form is shown on a page that is not encrypted.",
        "Anyone on the network can read the password as it is typed and sent.",
        "Serve every page containing a password field only over HTTPS."),
    "WEB-FORM-002": (
        "Form submits data to an HTTP address", "high", "Forms", "misconfiguration", "CWE-319",
        "A form sends what visitors type to an unencrypted address.",
        "Submitted data can be intercepted or altered in transit.",
        "Change the form action to an https:// address."),
    "WEB-FORM-003": (
        "Password form uses the GET method", "medium", "Forms", "misconfiguration", "CWE-598",
        "A form with a password field puts the data in the web address.",
        "Addresses are stored in browser history, logs and referrer headers.",
        "Use method=\"post\" for forms that send passwords or other sensitive data."),
    "WEB-FORM-004": (
        "POST form without a visible anti-CSRF token", "low", "Forms", "potential", "CWE-352",
        "A form that changes data does not appear to include a hidden security token.",
        "Without CSRF protection, another site could make a logged-in visitor submit the form unknowingly. "
        "Some sites protect against this differently (for example with SameSite cookies), so this needs review.",
        "Verify the application uses CSRF tokens or equivalent protection on state-changing forms."),
    "WEB-MIXED-001": (
        "Insecure (HTTP) script or frame loaded on an HTTPS page", "medium", "Transport security",
        "misconfiguration", "CWE-311",
        "An encrypted page loads code from an unencrypted address.",
        "Attackers can replace that code and take control of the page.",
        "Load every script, stylesheet and frame over https://."),
    "WEB-MIXED-002": (
        "Insecure (HTTP) images loaded on an HTTPS page", "low", "Transport security",
        "misconfiguration", "CWE-311",
        "An encrypted page loads images from an unencrypted address.",
        "Browsers may warn visitors, and content can be altered in transit.",
        "Load images over https://."),
    "WEB-SRI-001": (
        "External script loaded without Subresource Integrity", "low", "Supply chain", "potential",
        "CWE-353",
        "The page loads a script from another website without checking it has not been altered.",
        "If that third-party site is compromised, your visitors run the attacker's code.",
        "Add integrity and crossorigin attributes to third-party script tags, or host the files yourself."),
    "WEB-ACT-001": (
        "Sensitive file or endpoint is publicly accessible", "high", "Information disclosure",
        "misconfiguration", "CWE-538",
        "A file that should be private can be downloaded by anyone.",
        "Such files commonly contain passwords, keys or source code.",
        "Remove the file from the web root or block access in the server configuration, then rotate any exposed secrets."),
    "WEB-ACT-002": (
        "Risky HTTP method enabled", "medium", "Server configuration", "misconfiguration", "CWE-16",
        "The server accepts HTTP methods that are rarely needed and can be abused.",
        "TRACE can help attackers steal data in some browser attacks; open PUT/DELETE can allow changes.",
        "Disable TRACE and any methods the application does not need."),
    "WEB-ACT-003": (
        "Overly permissive CORS policy", "medium", "Cross-origin access", "misconfiguration", "CWE-942",
        "The site lets other websites read its responses from a visitor's browser.",
        "If combined with logins, a malicious site could read private data on behalf of a visitor.",
        "Allow only specific trusted origins; never reflect arbitrary origins, especially with credentials."),
    "WEB-ACT-004": (
        "Input is reflected without encoding (possible XSS)", "low", "Injection", "potential",
        "CWE-79",
        "Text sent in a web address is shown back on the page without being made safe.",
        "This is how cross-site scripting (XSS) usually starts. It must be confirmed by a person; this check only shows reflection.",
        "Encode output for the correct context (HTML, attribute, JavaScript) and validate input."),
    "WEB-INFO-001": (
        "security.txt contact file is not published", "info", "Security practices", "missing_control",
        "CWE-1059",
        "The site does not publish a file telling researchers how to report vulnerabilities.",
        "A clear contact route gets problems reported to you instead of being ignored or disclosed publicly.",
        "Publish /.well-known/security.txt (see https://securitytxt.org)."),
}

CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.75, "low": 0.4}
SCORE_DEDUCTION = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}

SCORE_METHODOLOGY = (
    "The security score starts at 100. Each distinct rule that fired deducts points by severity "
    "(critical 25, high 12, medium 5, low 2, informational 0), multiplied by confidence "
    "(high 1.0, medium 0.75, low 0.4). A rule that matches many times is counted once, so one noisy "
    "issue cannot zero the score. Observations are not scored. The score is a relative indicator "
    "of the checks that were run; it is not a guarantee that the target is secure."
)
