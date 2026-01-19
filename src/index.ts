import express from "express";
import { createNonce, consumeNonce, signState, verifyState } from "./state";
import { exchangeCodeAndStore, makeAuthUrl, gscSites, gscInspect } from "./google";

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name}`);
  return v;
}

const APP_URL = mustEnv("APP_URL");
const PORT = Number(process.env.PORT || 3000);

const app = express();
app.use(express.json({ limit: "1mb" }));

// Simple CORS (MVP)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", APP_URL);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// GET /oauth/google/start?workspaceId=demo
app.get("/oauth/google/start", (req, res) => {
  const workspaceId = String(req.query.workspaceId || "demo");
  const nonce = createNonce(workspaceId);
  const state = signState({ workspaceId, nonce, issuedAt: Date.now() });
  const url = makeAuthUrl(workspaceId, state);
  return res.redirect(url);
});

// GET /oauth/google/callback?code=...&state=...
app.get("/oauth/google/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const stateParam = String(req.query.state || "");

    if (!code || !stateParam) return res.status(400).send("Missing code or state");

    const state = verifyState(stateParam);
    const ok = consumeNonce(state.nonce, state.workspaceId);
    if (!ok) return res.status(400).send("Invalid or expired state/nonce");

    await exchangeCodeAndStore(state.workspaceId, code);

    return res.redirect(`${APP_URL}/settings/integrations?workspaceId=${encodeURIComponent(state.workspaceId)}&status=connected`);
  } catch (e: any) {
    return res.status(500).send(`OAuth callback error: ${e?.message || String(e)}`);
  }
});

// GET /gsc/sites?workspaceId=demo
app.get("/gsc/sites", async (req, res) => {
  try {
    const workspaceId = String(req.query.workspaceId || "demo");
    const data = await gscSites(workspaceId);
    res.json(data);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

// POST /gsc/inspect?workspaceId=demo  body { inspectionUrl, siteUrl, languageCode? }
app.post("/gsc/inspect", async (req, res) => {
  try {
    const workspaceId = String(req.query.workspaceId || "demo");
    const { inspectionUrl, siteUrl, languageCode } = req.body || {};

    if (!inspectionUrl || !siteUrl) {
      return res.status(400).json({ error: "Missing inspectionUrl or siteUrl" });
    }

    const data = await gscInspect(workspaceId, String(inspectionUrl), String(siteUrl), languageCode ? String(languageCode) : "en-US");
    res.json(data);
  } catch (e: any) {
    // URL Inspection often returns PERMISSION_DENIED; surface clearly.
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`GSC backend listening on port ${PORT}`);
});
