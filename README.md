# authority-capture-seo-backend (Express + TS)

Minimal backend for Google Search Console OAuth + test endpoints.

## Routes
- GET  /health
- GET  /oauth/google/start?workspaceId=demo
- GET  /oauth/google/callback
- GET  /gsc/sites?workspaceId=demo
- POST /gsc/inspect?workspaceId=demo  body: { inspectionUrl, siteUrl, languageCode? }

## Environment variables
Required:
- GOOGLE_OAUTH_CLIENT_ID
- GOOGLE_OAUTH_CLIENT_SECRET
- GOOGLE_OAUTH_REDIRECT_URI
- APP_URL
- ENCRYPTION_KEY (base64, 32 bytes)
Optional:
- PORT (default 3000)

Generate ENCRYPTION_KEY:
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

## Run locally
npm install
npm run dev

## Render deploy
1) Create a new Render Web Service from this GitHub repo.
2) Runtime: Node
3) Build Command:
   npm install && npm run build
4) Start Command:
   npm start
5) Set env vars in Render:
   - APP_URL = your Vercel frontend URL
   - GOOGLE_OAUTH_CLIENT_ID / SECRET from Google Cloud
   - GOOGLE_OAUTH_REDIRECT_URI = https://YOUR_RENDER_URL/oauth/google/callback
   - ENCRYPTION_KEY = (generated)

## Notes
URL Inspection requires your `siteUrl` property string to match exactly.
For URL-prefix properties it must end with a trailing slash, e.g. https://www.example.com/
Domain properties look like: sc-domain:example.com
