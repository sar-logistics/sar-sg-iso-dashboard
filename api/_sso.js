// Hub SSO session token (underscore prefix = not exposed as a Vercel route).
//
// /api/sso-verify exchanges the Hub's one-minute launch token for one of
// these, which the dashboard then sends as "Authorization: Bearer <token>"
// exactly where it would send a Google ID token. authenticate() in
// mongo.js accepts both and applies the same live role lookup to either.
//
// It is signed with a key derived from SSO_SHARED_SECRET and carries its own
// issuer and audience, so a Hub launch or widget token (same secret, issuer
// "sar-systems-hub") can never be replayed as a dashboard session.
import { createHmac } from "node:crypto";
import { SignJWT, jwtVerify, decodeJwt } from "jose";

export const SSO_SESSION_ISSUER = "sar-iso-sso-session";
const SSO_SESSION_AUDIENCE = "sar-sg-iso-dashboard";
// Same lifetime as a Google ID token, which is what the dashboard is built around.
export const SSO_SESSION_TTL_SEC = 60 * 60;

function sessionKey() {
  const secret = process.env.SSO_SHARED_SECRET;
  if (!secret) throw new Error("SSO_SHARED_SECRET is not set");
  return new Uint8Array(createHmac("sha256", secret).update("sar-iso-sso-session-v1").digest());
}

export async function mintSsoSession({ email, name }) {
  return new SignJWT({ name })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(email)
    .setIssuer(SSO_SESSION_ISSUER)
    .setAudience(SSO_SESSION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${SSO_SESSION_TTL_SEC}s`)
    .sign(sessionKey());
}

// Only decides which verifier to use. Nothing here is trusted: the token is
// fully verified (signature, issuer, audience, expiry) by verifySsoSession.
export function looksLikeSsoSession(token) {
  try { return decodeJwt(token).iss === SSO_SESSION_ISSUER; } catch { return false; }
}

export async function verifySsoSession(token) {
  const { payload } = await jwtVerify(token, sessionKey(), {
    issuer: SSO_SESSION_ISSUER, audience: SSO_SESSION_AUDIENCE, algorithms: ["HS256"],
  });
  const email = String(payload.sub || "").toLowerCase();
  if (!email) throw new Error("session token has no subject");
  return { email, name: payload.name || email };
}
