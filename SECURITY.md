# Security policy

## Reporting a vulnerability

Please report it through GitHub's private vulnerability reporting: open the **Security** tab of
this repository and choose **Report a vulnerability**. The report stays private between you and the
maintainer until a fix is ready. Please do not open a public issue for a vulnerability.

Useful in a report: what you did, what you expected, what happened, and the commit you tested.

## Out of scope

These are known limits, written in the threat model in [docs/security.md](docs/security.md#threat-model):

- A server that serves altered JavaScript, or a connection without TLS. The app does not terminate
  TLS: run it behind a proxy that does.
- Where the link is pasted. The key is in the link.
- A malicious browser extension.
- A bot or a person that clicks "Reveal" before the intended reader.
- Anyone who has the link spending the password attempts.
- Link plus read access to the database (the password is access control, not encryption).
- The 400 that uvicorn answers to a malformed request line, which carries none of the app's headers.
- Denial of service by volume, and findings that need a deployment this repository does not ship.
