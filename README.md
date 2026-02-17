# Gmail Email Responder (Multi-user, Render + OpenAI Assistant)

This service lets users connect their Gmail accounts, then it polls inboxes and drafts replies using an OpenAI Assistant.

## Quick Setup

### 1) Google Cloud OAuth (Gmail API + Google Login)
1. Create a Google Cloud project.
2. Enable the **Gmail API**.
3. Configure OAuth consent screen:
   - Type: External
   - Add your own email as a test user during development.
4. Create **OAuth Client ID**:
   - Application type: Web application
   - Authorized redirect URIs:
     - `https://YOUR_RENDER_URL.onrender.com/auth/google/callback`
     - `https://YOUR_RENDER_URL.onrender.com/gmail/connect/callback`
5. Copy the **Client ID** and **Client Secret** for env vars.

### 2) Create a Render Postgres database
Attach a Render Postgres DB and copy its connection string to `DATABASE_URL`.

### 3) Deploy to Render
Use the `render.yaml` blueprint or create a new **Web Service** pointing to this repo.

Set environment variables:
- `OPENAI_API_KEY`
- `OPENAI_ASSISTANT_ID`
- `DATABASE_URL`
- `SECRET_KEY`
- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`
- `GOOGLE_OAUTH_REDIRECT_URL` (the `/auth/google/callback` URL)
- `GMAIL_CLIENT_ID` (optional; falls back to Google OAuth client)
- `GMAIL_CLIENT_SECRET` (optional; falls back to Google OAuth client)
- `GMAIL_REDIRECT_URL` (the `/gmail/connect/callback` URL)
- `POLL_INTERVAL_SECONDS` (default 180)
- `EMERGENCY_CC_EMAIL` (optional; CC address for important/emergency emails)
- `EMERGENCY_CC_LEVEL` (`important` or `emergency`, default `important`)

### 4) User Login + Connect Gmail
1. Login with Google:
   `https://YOUR_RENDER_URL.onrender.com/auth/google/start`
2. Connect Gmail:
   `https://YOUR_RENDER_URL.onrender.com/gmail/connect/start`

### 5) Verify
- Health check: `https://YOUR_RENDER_URL.onrender.com/health`
- New unread emails should be answered automatically.

## Notes
- The poller ignores emails that are already marked read.
- Replies are sent in-thread and the email is marked as read afterward.
- To stop polling, set `RUN_POLLING=false`.
- If `EMERGENCY_CC_EMAIL` is set, the assistant will classify urgency and CC the address.

