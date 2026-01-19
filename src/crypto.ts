import crypto from "crypto";

function getKeyFromEnv(): Buffer {
  const b64 = process.env.ENCRYPTION_KEY;
  if (!b64) throw new Error("Missing ENCRYPTION_KEY env var (base64 32 bytes).");
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) throw new Error("ENCRYPTION_KEY must decode to 32 bytes (AES-256).");
  return key;
}

export function encryptString(plaintext: string): string {
  const key = getKeyFromEnv();
  const iv = crypto.randomBytes(12); // recommended length for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  // format: base64url(iv).base64url(tag).base64url(ciphertext)
  return [
    iv.toString("base64url"),
    tag.toString("base64url"),
    ciphertext.toString("base64url")
  ].join(".");
}

export function decryptString(blob: string): string {
  const key = getKeyFromEnv();
  const parts = blob.split(".");
  if (parts.length !== 3) throw new Error("Invalid encrypted blob format");
  const [ivB64, tagB64, ctB64] = parts;

  const iv = Buffer.from(ivB64, "base64url");
  const tag = Buffer.from(tagB64, "base64url");
  const ciphertext = Buffer.from(ctB64, "base64url");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}
