import crypto from "crypto";

type OAuthState = {
  workspaceId: string;
  nonce: string;
  issuedAt: number;
};

const NONCE_TTL_MS = 10 * 60 * 1000;
const nonceStore = new Map<string, { workspaceId: string; expiresAt: number }>();

function getStateSecret(): string {
  // Use ENCRYPTION_KEY as an HMAC secret too (fine for MVP)
  const s = process.env.ENCRYPTION_KEY;
  if (!s) throw new Error("Missing ENCRYPTION_KEY env var");
  return s;
}

export function createNonce(workspaceId: string): string {
  const nonce = crypto.randomBytes(16).toString("base64url");
  nonceStore.set(nonce, { workspaceId, expiresAt: Date.now() + NONCE_TTL_MS });
  return nonce;
}

export function consumeNonce(nonce: string, workspaceId: string): boolean {
  const entry = nonceStore.get(nonce);
  if (!entry) return false;
  nonceStore.delete(nonce);
  if (entry.workspaceId !== workspaceId) return false;
  if (Date.now() > entry.expiresAt) return false;
  return true;
}

function hmac(payloadB64: string): string {
  const secret = getStateSecret();
  return crypto.createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

export function signState(data: OAuthState): string {
  const payload = JSON.stringify(data);
  const payloadB64 = Buffer.from(payload, "utf8").toString("base64url");
  const sig = hmac(payloadB64);
  return `${payloadB64}.${sig}`;
}

export function verifyState(state: string): OAuthState {
  const parts = state.split(".");
  if (parts.length !== 2) throw new Error("Invalid state format");
  const [payloadB64, sig] = parts;
  const expected = hmac(payloadB64);
  if (sig !== expected) throw new Error("Invalid state signature");
  const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf8");
  return JSON.parse(payloadJson) as OAuthState;
}
