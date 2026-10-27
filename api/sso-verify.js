// POST /api/sso-verify — SAR Systems Hub SSO handoff.
//
// Verifies the Hub's one-minute launch token, applies the same access rules as
// the Google sign-in (roleFor: ADMIN_EMAILS, an enabled dashboardUsers entry, or
// ALLOWED_DOMAINS), and exchanges it for a dashboard session token (see _sso.js).
// The dashboard keeps its sign-in in memory only, so the token crosses the
// redirect in a one-shot sessionStorage key that the page's startup code moves
// into memory and deletes. Read-only: nothing is written here; the sign-in is
// recorded by the dashboard's own { dataset: "me", login: true } call.
import { jwtVerify } from "jose";
import { getDb, roleFor } from "./mongo.js";
import { mintSsoSession } from "./_sso.js";

const HUB_ISSUER = "sar-systems-hub";
const DEFAULT_HUB_ORIGIN = "https://systems.sarlogisolutions.com";

// Fallback only. The slug the Hub actually launched (staging or production
// entry) comes from the signature-verified token.
const DEFAULT_DASHBOARD_SLUG = "sar-iso-test";

// hub_origin decides where the widget script loads from, so only accept the
// Hub's own domain or its Vercel preview deployments.
function sanitizeHubOrigin(raw) {
  if (!raw) return DEFAULT_HUB_ORIGIN;
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return DEFAULT_HUB_ORIGIN;
    const h = u.hostname;
    if (h === "systems.sarlogisolutions.com" ||
        /^dashboards(-[a-z0-9]+)?-git-[a-z0-9-]+-sar-strategy\.vercel\.app$/.test(h)) return u.origin;
  } catch { /* fall through */ }
  return DEFAULT_HUB_ORIGIN;
}

// Safe to embed in an inline <script>.
const js = (v) => JSON.stringify(v == null ? "" : v)
  .replace(/</g, "\\u003c")
  .replace(/\u2028/g, "\\u2028")
  .replace(/\u2029/g, "\\u2029");

function handoffPage({ sessionToken, widgetToken, slug, hubOrigin }) {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Signing in…</title></head>
<body>
  <p>Signing you in…</p>
  <script>
    try {
      sessionStorage.setItem('sar_hub_sso_token', ${js(sessionToken)});
      var widgetToken = ${js(widgetToken)};
      if (widgetToken) {
        sessionStorage.setItem('sar_hub_widget_token', widgetToken);
        sessionStorage.setItem('sar_hub_current_slug', ${js(slug)});
        sessionStorage.setItem('sar_hub_origin', ${js(hubOrigin)});
      }
    } catch (e) {}
    location.replace('/');
  </script>
</body></html>`;
}

function formBody(req) {
  const b = req.body;
  if (typeof b === "string") return Object.fromEntries(new URLSearchParams(b));
  return b && typeof b === "object" ? b : {};
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).send("Method not allowed");

  const body = formBody(req);
  if (!body.sso_token) return res.status(400).send("Missing sso_token");

  const secret = process.env.SSO_SHARED_SECRET;
  if (!secret) {
    console.error("sso-verify: SSO_SHARED_SECRET is not set");
    return res.status(500).send("Server misconfiguration");
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(body.sso_token, new TextEncoder().encode(secret), { issuer: HUB_ISSUER }));
  } catch (err) {
    console.error("sso-verify: jwtVerify failed:", err.code || err.name, err.message);
    return res.status(401).send("Invalid or expired sign-in link. Please return to the Hub and try again.");
  }

  const email = String(payload.email || "").toLowerCase().trim();
  if (!email) return res.status(400).send("Token missing email");

  try {
    const role = await roleFor(email);
    if (!role) {
      return res.status(403).send("Access denied. Your account does not have access to this dashboard. Contact your administrator.");
    }
    // The Hub's token carries no display name; use the one on the user's
    // dashboardUsers entry if there is one, else the email.
    const entry = await (await getDb()).collection("dashboardUsers").findOne({ email }, { projection: { name: 1 } });
    const sessionToken = await mintSsoSession({ email, name: entry?.name || payload.name || email });

    const tokenSlug = typeof payload.slug === "string" ? payload.slug.trim() : "";
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(handoffPage({
      sessionToken,
      widgetToken: body.widget_token,
      slug: /^[a-z0-9][a-z0-9_-]{0,79}$/i.test(tokenSlug) ? tokenSlug : DEFAULT_DASHBOARD_SLUG,
      hubOrigin: sanitizeHubOrigin(body.hub_origin),
    }));
  } catch (err) {
    console.error("sso-verify error:", err);
    return res.status(500).send("Sign-in failed. Please try again.");
  }
}
