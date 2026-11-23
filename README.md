# DARKZONE Community

Arabic RTL community site built with Express, SQLite, sessions, and a responsive frontend.

## Features
- Account registration, login, logout
- Member profiles and editable bio
- Community posts and category filtering/search
- Likes and comments
- User reports
- Admin dashboard, report review, post deletion, announcement pinning
- Basic rate limiting and password hashing

## Run locally
1. Install Node.js 22 or newer.
2. Run `npm install`.
3. Set `SESSION_SECRET` to a long random secret.
4. Optionally set `ADMIN_EMAIL` to the email that should receive admin privileges.
5. Run `npm start`.

## Render deployment
- Build command: `npm install`
- Start command: `npm start`
- Set environment variables: `SESSION_SECRET` (required), `ADMIN_EMAIL` (recommended).
- Attach a persistent disk and set `DATA_DIR` to its mount path (for example `/var/data`) so SQLite data survives restarts/redeploys. Without a persistent disk, local SQLite data may be lost when the service is replaced.

## Important production note
For a public production service, configure a persistent disk and review session storage, backups, moderation, and privacy policies. The default Express session MemoryStore is not intended for production scale.
