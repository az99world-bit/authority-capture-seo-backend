import { OAuth2Client } from "google-auth-library";
import { getTokens, setTokens } from "./tokenStore";

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing ${name}`);
  return v;
}

export function oauthClient(): OAuth2Client {
  return new OAuth2Client({
    clientId: mustEnv("GOOGLE_OAUTH_CLIENT_ID"),
    clientSecret: mustEnv("GOOGLE_OAUTH_CLIENT_SECRET"),
    redirectUri: mustEnv("GOOGLE_OAUTH_REDIRECT_URI")
  });
}

export const GSC_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";

export function makeAuthUrl(workspaceId: string, state: string): string {
  const client = oauthClient();
  return client.generateAuthUrl({
    scope: [GSC_SCOPE],
    access_type: "offline",
    prompt: "consent",
    state
  });
}

export async function exchangeCodeAndStore(workspaceId: string, code: string): Promise<void> {
  const client = oauthClient();
  const { tokens } = await client.getToken(code);

  if (!tokens.access_token) throw new Error("No access_token returned from Google");
  if (!tokens.refresh_token) {
    // If user already consented previously, Google may omit refresh_token.
    // For MVP we require refresh_token to keep it working; user can disconnect/reconnect.
    throw new Error("No refresh_token returned. Try reconnecting with prompt=consent or revoke access and retry.");
  }
  const expiryDateMs = tokens.expiry_date ?? (Date.now() + 55 * 60 * 1000);

  setTokens(workspaceId, tokens.access_token, tokens.refresh_token, expiryDateMs, [GSC_SCOPE]);
}

async function getValidAccessToken(workspaceId: string): Promise<string> {
  const existing = getTokens(workspaceId);
  if (!existing) throw new Error("Workspace not connected to Google. Run /oauth/google/start first.");

  // refresh if expiring within 60 seconds
  if (Date.now() < existing.expiryDateMs - 60_000) return existing.accessToken;

  const client = oauthClient();
  client.setCredentials({ refresh_token: existing.refreshToken });

  // refreshAccessToken() is deprecated in some versions; getAccessToken() will refresh if needed.
  const accessTokenResponse = await client.getAccessToken();
  const accessToken = typeof accessTokenResponse === "string" ? accessTokenResponse : accessTokenResponse?.token;

  if (!accessToken) throw new Error("Failed to refresh access token");

  // Note: google-auth-library doesn't always return expiry_date here; keep current + 55 min as fallback
  const newExpiry = Date.now() + 55 * 60 * 1000;
  setTokens(workspaceId, accessToken, existing.refreshToken, newExpiry, existing.scopes);
  return accessToken;
}

export async function gscSites(workspaceId: string): Promise<any> {
  const token = await getValidAccessToken(workspaceId);
  const res = await fetch("https://www.googleapis.com/webmasters/v3/sites", {
    headers: { Authorization: `Bearer ${token}` }
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`GSC sites error ${res.status}: ${text}`);
  return JSON.parse(text);
}

export async function gscInspect(workspaceId: string, inspectionUrl: string, siteUrl: string, languageCode = "en-US"): Promise<any> {
  const token = await getValidAccessToken(workspaceId);

  const res = await fetch("https://searchconsole.googleapis.com/v1/urlInspection/index:inspect", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ inspectionUrl, siteUrl, languageCode })
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`URL Inspection error ${res.status}: ${text}`);
  return JSON.parse(text);
}
