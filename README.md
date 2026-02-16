# Gmail Email Responder (Render + OpenAI Assistant)

This service polls your Gmail inbox, drafts replies using an OpenAI Assistant, and sends the reply automatically.

## Quick Setup

### 1) Google Cloud OAuth (Gmail API)
1. Create a Google Cloud project.
2. Enable the **Gmail API**.
3. Configure OAuth consent screen:
   - Type: External
   - Add your Gmail address as a test user.
4. Create **OAuth Client ID**:
   - Application type: Web application
   - Authorized redirect URI: `https://YOUR_RENDER_URL.onrender.com/oauth/callback`
5. Copy the **Client ID** and **Client Secret** for env vars.

### 2) Deploy to Render
Use the `render.yaml` blueprint or create a new **Web Service** pointing to this repo.

Set environment variables:
- `OPENAI_API_KEY`
- `OPENAI_ASSISTANT_ID`
- `GMAIL_CLIENT_ID`
- `GMAIL_CLIENT_SECRET`
- `GMAIL_REDIRECT_URL` (the exact callback URL from step 1)
- `FROM_EMAIL` (your Gmail address)
- `POLL_INTERVAL_SECONDS` (default 180)
- `TOKEN_STORE_PATH` (default `/var/data/token_store.json`)

### 3) Connect Gmail
After the service is live, open:
`https://YOUR_RENDER_URL.onrender.com/oauth/start`

Complete the Google consent flow. Tokens are stored on the Render disk.

### 4) Verify
- Health check: `https://YOUR_RENDER_URL.onrender.com/health`
- New unread emails should be answered automatically.

## Notes
- The poller ignores emails that are already marked read.
- Replies are sent in-thread and the email is marked as read afterward.
- To stop polling, set `RUN_POLLING=false`.

