WebSentinel Authentication Upgrade
=================================

Included replacement files:
- backend/main.py
- frontend/src/App.jsx
- frontend/src/App.css

Install
-------
1. Stop the backend terminal with Ctrl+C.
2. Extract this ZIP into the existing web-vulnerability-scanner project folder and choose Replace files.
3. KEEP backend/websentinel_history.db. It contains your existing scan history. The new user/auth tables are added to that same database without deleting scans.
4. Start the backend from the project root:
   backend\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8002
5. Keep the existing frontend running and refresh http://localhost:5173.

Features
--------
- Signup with name, email and password (minimum 8 characters).
- Login with email and password.
- Passwords stored as salted PBKDF2-HMAC-SHA256 hashes; raw passwords are not stored.
- 12-hour server-side sessions; dashboard API endpoints require a bearer token.
- Logout invalidates the current session.
- Forgot password creates a one-time reset link that expires in 30 minutes and invalidates old sessions after a reset.
- Login/signup/reset errors are shown in the UI.

Forgot password and email
-------------------------
For local development, when SMTP is not configured, the Forgot Password page displays a development-only reset link inside the UI. It does not reveal whether an unknown email exists. This is intended only for localhost testing. Do NOT expose this mode on a public deployment. Set WEBSENTINEL_DEV_RESET_LINKS=false to disable development links.

To send real reset emails, configure environment variables before starting the backend:
  WEBSENTINEL_SMTP_HOST=your-smtp-host
  WEBSENTINEL_SMTP_PORT=587
  WEBSENTINEL_SMTP_USER=your-smtp-username
  WEBSENTINEL_SMTP_PASSWORD=your-smtp-password
  WEBSENTINEL_SMTP_FROM=verified-sender@example.com
  WEBSENTINEL_FRONTEND_URL=http://localhost:5173
  WEBSENTINEL_DEV_RESET_LINKS=false
Use your email provider's app password where required. Never commit SMTP credentials to source control.

Security notes
--------------
- This is a local learning project, not a production-ready identity system. Before public deployment, use HTTPS, secure environment configuration, rate limiting, CSRF protections where applicable, email verification, account recovery monitoring and a production-grade authentication provider.
- Only scan websites you own or have explicit permission to assess.
