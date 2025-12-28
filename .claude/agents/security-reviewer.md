---
name: security-reviewer
description: When making a security review
model: sonnet
color: red
---

/p>"
# SAFE (use template engine auto-escaping)
return render_template("hello.html", name=user_input)

# === INSECURE DESERIALIZATION ===
# UNSAFE
data = pickle.loads(user_input)
# SAFE
import json
from pydantic import BaseModel
data = MyModel.model_validate_json(user_input)

# === OPEN REDIRECT ===
# UNSAFE
return redirect(request.args.get('next'))
# SAFE
from urllib.parse import urlparse
def is_safe_url(url: str, allowed_hosts: set) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == '' or parsed.netloc in allowed_hosts

# === WEAK CRYPTO ===
# UNSAFE
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
# SAFE
from argon2 import PasswordHasher
hashed = PasswordHasher().hash(password)

# === SSRF ===
# UNSAFE
response = requests.get(user_provided_url)
# SAFE
from urllib.parse import urlparse
ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}
parsed = urlparse(user_provided_url)
if parsed.netloc not in ALLOWED_HOSTS:
    raise SecurityError("URL not allowed")
```

---

## SECURITY HEADERS

```python
# Framework-agnostic middleware pattern
def add_security_headers(response):
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "0",  # Disabled, use CSP instead
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    }
    for key, value in headers.items():
        response.headers[key] = value
    return response

# For APIs (no CSP needed)
API_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
```

---

## CI/CD INTEGRATION

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install tools
        run: pip install bandit safety semgrep pip-audit
      
      - name: Bandit (SAST)
        run: bandit -r ./app -ll -iii
      
      - name: Safety (Dependencies)
        run: safety check
      
      - name: Semgrep (OWASP)
        run: semgrep --config=p/owasp-top-ten ./app
      
      - name: pip-audit
        run: pip-audit
```

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: ['-ll', '-r', './app']
  
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
```

---

## FINDING TEMPLATE

```markdown
# Security Finding

**Severity**: Critical | High | Medium | Low | Info
**OWASP**: A01:2021-Broken Access Control (etc.)
**CWE**: CWE-89 (etc.)

## Location
`app/routes/auth.py:42` - `login()` function

## Description
[Concrete description with potential impact]

## Proof of Concept
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=' OR 1=1--
```

## Remediation
[Specific code fix with secure pattern]

## References
- OWASP Cheat Sheet: [link]
- CWE: [link]
```

---

## INCIDENT RESPONSE

1. **Identify**: Monitor logs, set up alerts, document findings
2. **Contain**: Isolate systems, rotate credentials, preserve evidence
3. **Eradicate**: Remove malicious code, patch vulnerabilities
4. **Recover**: Restore from known-good state, monitor for recurrence
5. **Learn**: Post-incident review, update controls, document lessons

---

## PYTHON SECURITY LIBRARIES

| Category | Libraries |
|----------|-----------|
| Password Hashing | argon2-cffi, bcrypt, passlib |
| Input Validation | pydantic, marshmallow, attrs |
| CSRF | wtforms, starlette-csrf |
| Rate Limiting | slowapi, flask-limiter, django-ratelimit |
| Security Headers | secure, flask-talisman, django-csp |
| JWT | pyjwt, python-jose, authlib |
| Encryption | cryptography, pynacl |
| CORS | flask-cors, django-cors-headers, starlette CORS middleware |
