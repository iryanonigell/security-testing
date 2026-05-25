# Security Testing — Intentionally Vulnerable Python App

> **WARNING**: This repository contains intentionally vulnerable code for the sole purpose of testing security scanning tools (SAST, DAST, secret scanners). Do NOT deploy this application.

## Purpose

Use this codebase to evaluate and calibrate security scanners such as:
- [Bandit](https://bandit.readthedocs.io/) — Python SAST
- [Semgrep](https://semgrep.dev/) — multi-language SAST
- [Snyk](https://snyk.io/) — dependency + code scanning
- [Gitleaks](https://gitleaks.io/) — secret scanning
- [Trivy](https://trivy.dev/) — vulnerability + secret scanning

## Vulnerability Coverage

| File | Vulnerability Types (CWE) |
|------|--------------------------|
| `app/auth.py` | SQL injection (89), weak hashing (328/760), hardcoded creds (798), insecure deserialization (502), command injection (78), timing attack (208) |
| `app/routes.py` | XSS (79), SSTI (94), path traversal (22), command injection (78), SQLi (89), open redirect (601), XXE (611), YAML injection (502), IDOR (639), CSRF (352), mass assignment (915) |
| `app/crypto.py` | Weak cipher (327), static IV (329), weak key size (326), broken algorithm (327), predictable random (338), hardcoded key (321), insufficient PBKDF2 iterations (916) |
| `app/database.py` | SQL injection (89), plaintext passwords (256), sensitive data in logs (532), hardcoded credentials (798) |
| `app/admin.py` | Missing auth (862), eval/exec injection (95), insecure deserialization (502), broken access control (284) |
| `app/network.py` | SSRF (918), SSL verification disabled (295), cleartext transmission (319), email header injection (93) |
| `app/file_handler.py` | Unrestricted upload (434), path traversal/zip slip (22), insecure temp file (377), command injection via filename (78) |
| `app/serializers.py` | Insecure deserialization (502), YAML unsafe load (502) |
| `app/logging_utils.py` | Sensitive data in logs (532), log injection (117), debug in production (11) |
| `app/utils.py` | ReDoS (1333), predictable tokens (330), IP spoofing (807), TOCTOU (362), integer overflow (190) |
| `app/ssh_client.py` | Host key bypass (295), hardcoded private key (321), remote command injection (78) |
| `app/config.py` | Hardcoded credentials (798), insecure session config, debug mode enabled |
| `.env.example` | Secret key patterns for secret scanner testing |

## Running Scanners

```bash
# Bandit
pip install bandit
bandit -r app/ -ll

# Semgrep
semgrep --config=p/python app/

# Gitleaks
gitleaks detect --source . --verbose

# Trivy
trivy fs .
```
