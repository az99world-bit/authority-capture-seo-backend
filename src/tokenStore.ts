import { encryptString, decryptString } from "./crypto";

export type StoredTokens = {
  accessTokenEnc: string;
  refreshTokenEnc: string;
  expiryDateMs: number; // epoch ms
  scopes: string[];
  updatedAt: number;
};

const store = new Map<string, StoredTokens>(); // workspaceId -> tokens

export function setTokens(workspaceId: string, accessToken: string, refreshToken: string, expiryDateMs: number, scopes: string[]) {
  store.set(workspaceId, {
    accessTokenEnc: encryptString(accessToken),
    refreshTokenEnc: encryptString(refreshToken),
    expiryDateMs,
    scopes,
    updatedAt: Date.now()
  });
}

export function getTokens(workspaceId: string): { accessToken: string; refreshToken: string; expiryDateMs: number; scopes: string[] } | null {
  const t = store.get(workspaceId);
  if (!t) return null;
  return {
    accessToken: decryptString(t.accessTokenEnc),
    refreshToken: decryptString(t.refreshTokenEnc),
    expiryDateMs: t.expiryDateMs,
    scopes: t.scopes
  };
}
