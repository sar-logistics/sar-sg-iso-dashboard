// SAR ISO Tank SG dashboard — MongoDB API (Vercel serverless function).
//
//   GET  /api/mongo?config=1              -> { googleClientId }            (public)
//   POST /api/mongo  { dataset: "sales" } -> sales lines for the dashboard (signed in)
//   POST /api/mongo  { dataset: "mr" }    -> current tank inventory for M&R Operations (signed in)
//   POST /api/mongo  { dataset: "deploy" } -> export BLs with their tanks for Tank Deployment (signed in)
//   POST /api/mongo  { dataset: "finance" } -> open receivable / payable invoices with due dates (signed in)
//   POST /api/mongo  { dataset: "financeRemarks" } -> remarks per party (signed in)
//   POST /api/mongo  { action: "saveFinanceRemark", side: "ar"|"ap", party, remark?, onAccount? } -> remarks  (admins;
//                    onAccount: number = amount received / paid on account, null = clear and use SARFD's figure)
//   POST /api/mongo  { dataset: "me" }    -> { email, name, role }        (signed in; login: true also records a sign-in)
//   POST /api/mongo  { dataset: "usage" } -> sign-in stats per user + logins per day  (admins)
//   POST /api/mongo  { collection, pipeline } -> read-only aggregate      (signed in)
//   POST /api/mongo  { dataset: "users" }                 -> users with access     (admins)
//   POST /api/mongo  { action: "saveUser", email, name, role, disabled, create } -> users  (admins)
//   POST /api/mongo  { action: "bulkSaveUsers", users: [{ email, name, role }] } -> { users, added, updated, unchanged, skipped }  (admins)
//   POST /api/mongo  { action: "deleteUser", email }       -> users                 (admins)
//
// Every POST needs "Authorization: Bearer <Google ID token>" from Google sign-in.
// Environment: MONGODB_URI, MONGODB_DB, ADMIN_EMAILS, ALLOWED_DOMAINS (GOOGLE_CLIENT_ID optional).

import { MongoClient, Binary } from "mongodb";
import { createHash } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { looksLikeSsoSession, verifySsoSession } from "./_sso.js";

const DB_NAME = process.env.MONGODB_DB || "sar_iso_dashboard";
// Google OAuth Web client (project "sar-iso-dashboard"). Not a secret; GOOGLE_CLIENT_ID overrides it.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "416635306158-uekjjb4k7barhpr7k8s774r9hskmt9an.apps.googleusercontent.com";

// ---------------------------------------------------------------- database

const g = globalThis;
export async function getDb() {
  if (!process.env.MONGODB_URI) throw new HttpError(500, "MONGODB_URI is not set");
  if (!g._sarMongo) {
    g._sarMongo = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 8000, maxPoolSize: 5 }).connect();
    g._sarMongo.catch(() => { g._sarMongo = undefined; });
  }
  return (await g._sarMongo).db(DB_NAME);
}

export class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

// ---------------------------------------------------------------- sign-in

const list = (v) => (v || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

/** admin: ADMIN_EMAILS or dashboardUsers role "admin"; viewer: dashboardUsers or ALLOWED_DOMAINS. */
export async function roleFor(email) {
  const e = email.toLowerCase();
  if (list(process.env.ADMIN_EMAILS).includes(e)) return "admin";
  const db = await getDb();
  const user = await db.collection("dashboardUsers").findOne({ email: e, disabled: { $ne: true } }, { projection: { role: 1 } });
  if (user) return user.role === "admin" ? "admin" : "viewer";
  if (list(process.env.ALLOWED_DOMAINS).includes(e.split("@")[1])) return "viewer";
  return null;
}

const tokenCache = new Map(); // idToken -> { user, exp }

async function verifyGoogleToken(idToken) {
  const hit = tokenCache.get(idToken);
  if (hit && hit.exp > Date.now()) return hit.user;

  const clientId = GOOGLE_CLIENT_ID;
  const r = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  if (!r.ok) throw new HttpError(401, "Sign-in expired. Please sign in again.");
  const t = await r.json();
  const expMs = Number(t.exp) * 1000;
  if (t.aud !== clientId || !["accounts.google.com", "https://accounts.google.com"].includes(t.iss)
      || String(t.email_verified) !== "true" || !(expMs > Date.now())) {
    throw new HttpError(401, "Sign-in expired. Please sign in again.");
  }
  const user = { email: t.email.toLowerCase(), name: t.name || t.email };
  if (tokenCache.size > 500) tokenCache.clear();
  tokenCache.set(idToken, { user, exp: expMs });
  return user;
}

/**
 * Returns { email, name, role } or throws 401/403. Accepts a Google ID token or a
 * Hub SSO session token (see _sso.js); the role is looked up live for either.
 */
export async function authenticate(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) throw new HttpError(401, "Not signed in");
  const token = h.slice(7);
  let user;
  if (looksLikeSsoSession(token)) {
    try { user = await verifySsoSession(token); }
    catch (e) { throw new HttpError(401, "Sign-in expired. Please sign in again."); }
  } else {
    user = await verifyGoogleToken(token);
  }
  const role = await roleFor(user.email);
  if (!role) throw new HttpError(403, `${user.email} does not have access to this dashboard`, "no_access");
  return { ...user, role };
}

// ---------------------------------------------------------------- read-only queries

const READABLE = new Set([
  "tblBL", "tblCompany", "tblContainerMovement", "tblContainerRepair", "tblContainerTransaction",
  "tblInvoice", "tblJob", "tblRateRequest", "tblVoucher", "chargeMappings", "sarfdSyncHistory",
]);
const FORBIDDEN = new Set(["$out", "$merge", "$function", "$accumulator", "$where", "$currentOp",
  "$listSessions", "$listLocalSessions", "$planCacheStats", "$collStats", "$indexStats"]);
const MAX_DOCS = 20000;

function checkPipeline(node) {
  if (Array.isArray(node)) return node.forEach(checkPipeline);
  if (!node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    if (FORBIDDEN.has(k)) throw new HttpError(400, `${k} is not allowed`);
    if (k === "$lookup" || k === "$graphLookup") {
      if (!READABLE.has(v?.from)) throw new HttpError(400, `Cannot read collection ${v?.from}`);
    }
    if (k === "$unionWith") {
      const coll = typeof v === "string" ? v : v?.coll;
      if (!READABLE.has(coll)) throw new HttpError(400, `Cannot read collection ${coll}`);
    }
    checkPipeline(v);
  }
}

async function aggregate(collection, pipeline = []) {
  if (!READABLE.has(collection)) throw new HttpError(400, `Unknown collection ${collection}`);
  if (!Array.isArray(pipeline)) throw new HttpError(400, "pipeline must be an array");
  checkPipeline(pipeline);
  const db = await getDb();
  const docs = await db.collection(collection)
    .aggregate([...pipeline, { $limit: MAX_DOCS + 1 }], { maxTimeMS: 20000 }).toArray();
  return { docs: docs.slice(0, MAX_DOCS), truncated: docs.length > MAX_DOCS };
}

// ---------------------------------------------------------------- sales dataset

// Same rules as the ERP "Invoice Register Chargewise Rowwise" report behind the weekly-call
// "1. Billing details" sheet (checked line by line, Feb–Aug 2026 match to the cent):
//   - sales vouchers only: Principal Sales, Sub Lease, Sundry, M&R Sales invoices and Principal Credit Notes
//     (Debit Note Agency, purchase vouchers and proformas are not revenue)
//   - company SAR Global PTE Ltd, plus the old company's (SAR LOGISOLUTIONS PTE. LTD.) January 2026 invoices
//   - proforma invoices (invoice number starting "PRO") left out even when filed under a sales voucher
//   - invoices carrying a deletedNo are kept: they are still posted in the ledger and in the report
const SALES_VOUCHERS = { PSI: "Invoice", SLI: "Invoice", SDI: "Invoice", MRI: "Invoice", CN: "Credit Note" };
const SALES_COMPANIES = ["SAR Global PTE Ltd"];
// Credit notes against invoices dated before 2026 are left out (e.g. the Principle Credit Notes entered in Oct-26,
// dated Jan-26, that credit DEM-IMP invoices of Apr–Sep 2025): the Performance report only covers 2026 billing.
const CN_PARENT_FROM = new Date("2026-01-01T00:00:00Z");
// SAR Global was SAR LOGISOLUTIONS PTE. LTD. until the rename in Feb 2026; its January 2026 invoices and BLs
// are shown too, so Jan-26 has figures. Earlier months of the old company stay out.
const OLD_COMPANY = "SAR LOGISOLUTIONS PTE. LTD.";
const OLD_COMPANY_MONTHS = ["2026-01"];
const keepCompany = (company, date) => SALES_COMPANIES.includes(company) || (company === OLD_COMPANY && OLD_COMPANY_MONTHS.includes(String(date).slice(0, 7)));
const SUNDRY = new Set(["SDI"]);
const COUNTRY_FIX = { "SOUTH ,KOREA": "South Korea" };   // SARFD spelling slips
const tidyCountry = (v) => { const c = s(v).replace(/\s+/g, " "); return COUNTRY_FIX[c.toUpperCase()] || c; };
// Country → trade lane (region) from the "Tradelane Mappings" sheet, column C, loaded into tradelaneMappings by
// sarfd_sync.py. Documents are keyed by countryKey (keep in step with country_key() in sarfd_sync.py).
const countryKey = (v) => String(v ?? "").replace(/,/g, " ").replace(/\s+/g, " ").trim().toUpperCase();
const CATEGORIES = ["Lease", "Detention", "EXIM", "M&R", "Other"];
const s = (v) => (typeof v === "string" ? v.trim() : "");
const normCharge = (v) => s(v).toUpperCase();

async function buildSales(db, mappings, lastSync, tradelanes = []) {
  const catOf = new Map(mappings.map((m) => [normCharge(m.chargeName), CATEGORIES.includes(m.revenueCategory) ? m.revenueCategory : "Other"]));
  // Basket (Billing Details grouping) from the "Syscon Charges" sheet, loaded into chargeMappings.basket
  const basketOf = new Map(mappings.filter((m) => s(m.basket)).map((m) => [normCharge(m.chargeName), s(m.basket)]));
  const rows = await db.collection("tblInvoice").find(
    { recordType: "C", voucherCode: { $in: Object.keys(SALES_VOUCHERS) }, companyName: { $in: [...SALES_COMPANIES, OLD_COMPANY] }, invoiceNo: { $not: /^PRO/i } },
    { projection: { _id: 0, companyName: 1, invoiceId: 1, invoiceNo: 1, invoiceDate: 1, voucherCode: 1, lineNo: 1, chargeName: 1,
        chargeTotalAmountHc: 1, billingPartyName: 1, shipperName: 1, polName: 1, podName: 1, blNo: 1, jobNo: 1, parentInvoiceDate: 1 } },
  ).toArray();
  // Trade lane by country: the invoice's job (tblJob.jobNo) carries origin and destination country.
  // Checked 2026-10-22: every line with a POL → POD lane has a job with both countries, and they match the BL's POL / POD countries.
  // Trade lane = origin trade lane → destination trade lane (each country's region from the mapping sheet;
  // a country missing from the sheet shows under its own name).
  const regionOf = new Map(tradelanes.map((t) => [t._id, s(t.tradelane)]));
  const region = (c) => regionOf.get(countryKey(c)) || c;
  const jobCountries = new Map();
  for (const j of await db.collection("tblJob").find({ jobNo: { $nin: [null, ""] } }, { projection: { _id: 0, jobNo: 1, originCountryName: 1, destinationCountryName: 1 } }).toArray()) {
    const o = tidyCountry(j.originCountryName), d = tidyCountry(j.destinationCountryName), k = s(j.jobNo).toUpperCase();
    if (o && d && !jobCountries.has(k)) jobCountries.set(k, { country: `${o} → ${d}`, trade: `${region(o)} → ${region(d)}` });
  }

  const lines = [];
  for (const r of rows) {
    if (!r.invoiceDate || !keepCompany(r.companyName, new Date(r.invoiceDate).toISOString())) continue;
    const docType = SALES_VOUCHERS[r.voucherCode];
    if (docType === "Credit Note" && r.parentInvoiceDate && new Date(r.parentInvoiceDate) < CN_PARENT_FROM) continue;   // credits a pre-2026 invoice
    const pol = s(r.polName), pod = s(r.podName), blNo = s(r.blNo);
    const charge = normCharge(r.chargeName) || "(NO CHARGE NAME)";
    lines.push({
      id: `${r.invoiceId}-${r.lineNo ?? lines.length}`,
      invoiceId: r.invoiceId,
      invoiceNo: s(r.invoiceNo),
      date: new Date(r.invoiceDate).toISOString().slice(0, 10),
      docType,
      charge,
      category: catOf.get(charge) ?? "Other",
      basket: basketOf.get(charge) || "(Not mapped)",
      amount: (docType === "Credit Note" ? -1 : 1) * (r.chargeTotalAmountHc ?? 0),  // USD, credit notes negative
      agent: s(r.billingPartyName) || "(Unknown)",
      shipper: s(r.shipperName),
      pol, pod,
      lane: blNo && pol && pod && !SUNDRY.has(r.voucherCode) ? `${pol} → ${pod}` : null,
      ...(() => {   // countryLane = origin → destination country, tradeLane = their trade lanes (regions)
        const jc = blNo && pol && pod && !SUNDRY.has(r.voucherCode) ? jobCountries.get(s(r.jobNo).toUpperCase()) : null;
        return { countryLane: jc?.country || null, tradeLane: jc?.trade || null };
      })(),
      blNo,
      jobNo: s(r.jobNo),
    });
  }
  lines.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  return { lines, lastSync, generatedAt: new Date().toISOString() };
}

// The Atlas cluster downloads slowly (~100 KB/s), so the built dataset is kept gzipped in
// `dashboardCache` and rebuilt only after a new tblInvoice sync or a charge-mapping change.
const TTL_MS = 2 * 60 * 1000;
const SNAPSHOT_ID = "sales-html-v7";

async function salesDataset() {
  if (g._sarSales && Date.now() - g._sarSales.at < TTL_MS) return g._sarSales.data;
  const data = (async () => {
    const db = await getDb();
    const [mappings, last, tradelanes] = await Promise.all([
      db.collection("chargeMappings").find({}, { projection: { _id: 0, chargeName: 1, revenueCategory: 1, basket: 1 } }).toArray(),
      db.collection("sarfdSyncHistory").findOne(
        { table: "tblInvoice", status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } },
        { sort: { startedAt: -1 }, projection: { startedAt: 1 } }),
      db.collection("tradelaneMappings").find({}, { projection: { tradelane: 1 } }).toArray(),
    ]);
    const lastSync = last?.startedAt ? new Date(last.startedAt).toISOString() : null;
    const mapKey = mappings.map((m) => `${normCharge(m.chargeName)}=${m.revenueCategory}/${m.basket || ""}`).sort().join("|");
    const laneKey = tradelanes.map((t) => `${t._id}=${t.tradelane}`).sort().join("|");   // a trade-lane sheet change rebuilds the data
    const key = createHash("sha1").update(`${lastSync}|${mapKey}|${laneKey}`).digest("hex");

    const cache = db.collection("dashboardCache");
    const snap = await cache.findOne({ _id: SNAPSHOT_ID });
    if (snap?.key === key) return JSON.parse(gunzipSync(snap.gz.buffer).toString("utf8"));

    const payload = await buildSales(db, mappings, lastSync, tradelanes);
    const gz = new Binary(gzipSync(Buffer.from(JSON.stringify(payload))));
    await cache.replaceOne({ _id: SNAPSHOT_ID }, { key, gz, builtAt: new Date() }, { upsert: true });
    return payload;
  })();
  g._sarSales = { at: Date.now(), data };
  data.catch(() => { g._sarSales = undefined; });
  return data;
}

// ---------------------------------------------------------------- M&R Operations dataset
//
// One row per tank in the fleet. The fleet is every tank in tblContainerMovement whose latest movement
// (activityDate desc, then containerMovementId desc, rows with a deletedNo left out) is not OFF HIRE —
// the same list as Syscon's "Current Inventory" report (checked tank by tank: 1,022 = 1,022, 21 Oct 2026).
// Tanks with a movement but no container transaction (77 on that date) are part of the fleet. Principal is the company on the tank's latest On Hire
// transaction; older transactions have no company and belong to SAR LOGISOLUTIONS PTE. LTD.
// (tblContainerRepair.principalName and tblInvoice.principalName are blank for most tanks).

const DEFAULT_PRINCIPAL = "SAR LOGISOLUTIONS PTE. LTD.";
const MR_SNAPSHOT_ID = "mr-inventory-v4";
const OFF_HIRE_ACTIVITY = "OFF HIRE";
const MR_SYNC_TABLES = ["tblContainerMovement", "tblContainerTransaction", "tblJob", "tblInvoice"];

/** Status bucket from the activity name (keyword rules from the requirements document). */
function mrBucket(activity) {
  const a = activity.toUpperCase();
  if (a.includes("EMPTY")) return "Empty";
  if (a.includes("LOADED")) return "Loaded Full";
  if (a.includes("SENT TO CONSIGNEE")) return "Sent to Consignee";
  if (a.includes("ON HIRE")) return "On Lease";              // SUB LEASE ON HIRE, ON HIRE (not SUB LEASE OFF HIRE)
  if (a.includes("CLEAN") || a.includes("WASH")) return "Under Cleaning";
  if (a.includes("REPAIR")) return "Under Repair";
  if (a.includes("SURVEY")) return "Under Survey";
  return "Other";
}

async function buildMr(db, lastSync) {
  const [txns, latest] = await Promise.all([
    db.collection("tblContainerTransaction").find({}, { projection: { _id: 0, containerTransactionNo: 1, containerTransactionId: 1,
      containerTransactionDate: 1, pageTypeName: 1, companyName: 1, partyName: 1, detailContainerNo: 1 } }).toArray(),
    db.collection("tblContainerMovement").aggregate([
      { $match: { deletedNo: { $exists: false } } },
      { $sort: { activityDate: -1, containerMovementId: -1 } },
      { $group: { _id: "$containerNo", m: { $first: "$$ROOT" } } },
      { $project: { _id: 0, c: "$_id", size: "$m.sizeName", type: "$m.typeName", activity: "$m.activityName", date: "$m.activityDate",
                    agent: "$m.agentName", agentBranch: "$m.agentBranchName", from: "$m.fromLocationName", to: "$m.toLocationName",
                    vessel: "$m.vesselName", voyage: "$m.voyageNo", jobNo: "$m.jobNo", importBl: "$m.importBlNo", exportBl: "$m.exportBlNo" } },
    ], { allowDiskUse: true }).toArray(),
  ]);

  // company per transaction (it is only on some rows of a transaction), then the latest On Hire per tank
  const company = new Map();
  for (const t of txns) if (s(t.companyName) && !company.has(t.containerTransactionNo)) company.set(t.containerTransactionNo, s(t.companyName));
  const byTank = new Map();
  for (const t of txns) {
    const c = s(t.detailContainerNo); if (!c) continue;
    const key = [t.containerTransactionDate ? +new Date(t.containerTransactionDate) : 0, t.containerTransactionId || 0];
    const cur = byTank.get(c) || { on: null, any: null };
    const newer = (x) => !x || key[0] > x.key[0] || (key[0] === x.key[0] && key[1] > x.key[1]);
    const entry = { key, company: company.get(t.containerTransactionNo) || "", party: s(t.partyName), page: s(t.pageTypeName) };
    if (t.pageTypeName === "On Hire" && newer(cur.on)) cur.on = entry;
    if (newer(cur.any)) cur.any = entry;
    byTank.set(c, cur);
  }

  const move = new Map(latest.map((m) => [s(m.c), m]));
  const depots = await buildDepots(db);
  const day = (d) => (d ? new Date(d).toISOString().slice(0, 10) : null);
  const tanks = [];
  let offHire = 0;
  for (const [c, m] of move) {
    if (!c) continue;
    const activity = s(m.activity) || "(NO MOVEMENT)";
    if (activity.toUpperCase() === OFF_HIRE_ACTIVITY) { offHire++; continue; }   // back with the lessor: not in the fleet
    const t = byTank.get(c) || {};
    tanks.push({
      c, size: s(m.size), type: s(m.type), activity, bucket: mrBucket(activity), date: day(m.date),
      principal: t.on?.company || t.any?.company || DEFAULT_PRINCIPAL,
      lessor: t.on?.party || "",
      agent: s(m.agent) || "(Unknown)", agentBranch: s(m.agentBranch),
      from: s(m.from), to: s(m.to), vessel: s(m.vessel), voyage: s(m.voyage),
      jobNo: m.jobNo == null ? "" : String(m.jobNo).trim(), importBl: s(m.importBl), exportBl: s(m.exportBl),
    });
  }
  tanks.sort((a, b) => a.c.localeCompare(b.c));
  const dataTo = latest.reduce((mx, m) => (m.date && +new Date(m.date) > mx ? +new Date(m.date) : mx), 0);
  return { tanks, offHire, depots, lastSync, dataTo: dataTo ? day(dataTo) : null, generatedAt: new Date().toISOString() };
}

// Depot details for the Tank Inventory report, all from SARFD (key = upper-cased depot / location name):
//   country       tblJob.originCountryName of jobs whose containerDepotName is the depot,
//                 else tblBL.podCountryName of the import BLs of tanks moved into the depot (tblContainerMovement.importBlNo),
//                 else the country of the depot's port (tblJob POL/POD -> origin/destination country)
//   port          tblJob.polName of the depot's jobs, else where its empty tanks come in from (tblContainerMovement)
//   agent         tblContainerMovement.agentName of movements into the depot
//   billingParty  tblInvoice.billingPartyName of invoices with that depotName
// Each value is the most common one. Blanks get the most common value of similar depots:
//   country       -> most common country of depots with the same agent, then overall
//   billingParty  -> most common of depots in the same country, then the depot's agent
//   port / agent  -> most common of depots in the same country, then overall
const locKey = (v) => s(v).replace(/\s+/g, " ").toUpperCase();
const cleanParty = (v) => s(v).replace(/\s*-\s*cr\.?(?=\s|$)/gi, "").replace(/\s+/g, " ").trim();
const cleanCountry = (v) => s(v).replace(/\s*,\s*/g, " ").replace(/\s+/g, " ").trim();
const INBOUND = ["PORT TO DEPOT EMPTY", "EMPTY RECEIVED FROM CONSIGNEE", "DEPOT EMPTY IN", "IMPORT DISCHARGE EMPTY", "EMPTY RETURN BY SHIPPER"];

async function buildDepots(db) {
  const group = (k, v) => ({ $group: { _id: { k: k, v: v }, n: { $sum: 1 } } });
  const [jobDepot, portCountryPol, portCountryPod, inbound, agents, billing, importBls, blCountry] = await Promise.all([
    db.collection("tblJob").aggregate([{ $match: { containerDepotName: { $nin: [null, ""] } } },
      { $group: { _id: { k: "$containerDepotName", c: "$originCountryName", p: "$polName" }, n: { $sum: 1 } } }]).toArray(),
    db.collection("tblJob").aggregate([group("$polName", "$originCountryName")]).toArray(),
    db.collection("tblJob").aggregate([group("$podName", "$destinationCountryName")]).toArray(),
    db.collection("tblContainerMovement").aggregate([{ $match: { activityName: { $in: INBOUND }, deletedNo: { $exists: false } } },
      group("$toLocationName", "$fromLocationName")]).toArray(),
    db.collection("tblContainerMovement").aggregate([{ $match: { deletedNo: { $exists: false } } }, group("$toLocationName", "$agentName")]).toArray(),
    db.collection("tblInvoice").aggregate([{ $match: { depotName: { $nin: [null, ""] } } }, group("$depotName", "$billingPartyName")]).toArray(),
    db.collection("tblContainerMovement").aggregate([{ $match: { importBlNo: { $nin: [null, ""] }, deletedNo: { $exists: false } } },
      group("$toLocationName", "$importBlNo")]).toArray(),
    db.collection("tblBL").aggregate([{ $match: { blNo: { $nin: [null, ""] }, podCountryName: { $nin: [null, ""] } } },
      { $group: { _id: "$blNo", c: { $first: "$podCountryName" } } }]).toArray(),
  ]);

  // tallies: key -> value -> count
  const tally = () => new Map();
  const add = (t, k, v, n) => { k = locKey(k); v = s(v); if (!k || !v) return; const m = t.get(k) || new Map(); m.set(v, (m.get(v) || 0) + n); t.set(k, m); };
  const top = (t, k) => { const m = t.get(k); if (!m) return ""; let best = "", bn = 0; for (const [v, n] of m) if (n > bn) { best = v; bn = n; } return best; };
  const country = tally(), blCtry = tally(), jobPort = tally(), portCountry = tally(), fromPort = tally(), agent = tally(), bill = tally();
  for (const r of jobDepot) { add(country, r._id.k, cleanCountry(r._id.c), r.n); add(jobPort, r._id.k, r._id.p, r.n); }
  for (const r of [...portCountryPol, ...portCountryPod]) add(portCountry, r._id.k, cleanCountry(r._id.v), r.n);
  const podOf = new Map(blCountry.map((b) => [locKey(b._id), cleanCountry(b.c)]));
  for (const r of importBls) add(blCtry, r._id.k, podOf.get(locKey(r._id.v)), r.n);
  for (const r of inbound) if (locKey(r._id.v) !== locKey(r._id.k) && !/^SUB LEASE/i.test(s(r._id.v))) add(fromPort, r._id.k, r._id.v, r.n);
  for (const r of agents) add(agent, r._id.k, r._id.v, r.n);
  for (const r of billing) add(bill, r._id.k, cleanParty(r._id.v), r.n);

  const keys = new Set([...country.keys(), ...blCtry.keys(), ...jobPort.keys(), ...fromPort.keys(), ...agent.keys(), ...bill.keys()]);
  const out = {};
  for (const k of keys) {
    const port = top(jobPort, k) || top(fromPort, k);
    out[k] = { country: top(country, k) || top(blCtry, k) || top(portCountry, locKey(port)), port, agent: top(agent, k), billingParty: top(bill, k) };
  }
  // blanks: most common value among similar depots (see above)
  const commonBy = (field, by) => {
    const t = tally();
    for (const d of Object.values(out)) if (d[field]) add(t, by ? d[by] || "-" : "ALL", d[field], 1);
    return (d) => top(t, by ? locKey(d[by] || "-") : "ALL");
  };
  const fill = (d, f, v) => { if (!d[f] && v) { d[f] = v; d.filled = [...(d.filled || []), f]; } };
  const ctryByAgent = commonBy("country", "agent"), ctryAll = commonBy("country");
  for (const d of Object.values(out)) fill(d, "country", ctryByAgent(d) || ctryAll(d));
  for (const f of ["port", "agent"]) {
    const sameCountry = commonBy(f, "country"), overall = commonBy(f);
    for (const d of Object.values(out)) fill(d, f, sameCountry(d) || overall(d));
  }
  const billByCountry = commonBy("billingParty", "country"), billAll = commonBy("billingParty");
  for (const d of Object.values(out)) fill(d, "billingParty", billByCountry(d) || d.agent || billAll(d));
  return out;
}

async function mrDataset() {
  if (g._sarMr && Date.now() - g._sarMr.at < TTL_MS) return g._sarMr.data;
  const data = (async () => {
    const db = await getDb();
    const syncs = await Promise.all(MR_SYNC_TABLES.map((table) =>
      db.collection("sarfdSyncHistory").findOne(
        { table, status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } },
        { sort: { startedAt: -1 }, projection: { startedAt: 1 } })));
    const times = syncs.map((x) => (x?.startedAt ? new Date(x.startedAt).toISOString() : null));
    const lastSync = times.filter(Boolean).sort().pop() || null;
    const key = createHash("sha1").update(`${MR_SNAPSHOT_ID}|${times.join("|")}`).digest("hex");

    const cache = db.collection("dashboardCache");
    const snap = await cache.findOne({ _id: MR_SNAPSHOT_ID });
    if (snap?.key === key) return JSON.parse(gunzipSync(snap.gz.buffer).toString("utf8"));

    const payload = await buildMr(db, lastSync);
    const gz = new Binary(gzipSync(Buffer.from(JSON.stringify(payload))));
    await cache.replaceOne({ _id: MR_SNAPSHOT_ID }, { key, gz, builtAt: new Date() }, { upsert: true });
    return payload;
  })();
  g._sarMr = { at: Date.now(), data };
  data.catch(() => { g._sarMr = undefined; });
  return data;
}

// ---------------------------------------------------------------- Tank Deployment dataset
// One row per export BL (tblBL, header rows "H") with its tanks (detail rows "D", container_containerNo).
// Same rules as the Syscon "BL Register - Dump" pivot it replaces: SAR Global PTE Ltd BLs (plus the old company's
// January 2026 BLs), month from the
// HBL date, tanks = the BL's live container list. Checked BL by BL against the dump (Feb–Sep 2026).

const DEPLOY_COMPANIES = ["SAR Global PTE Ltd"];
const DEPLOY_SNAPSHOT_ID = "deploy-v2";
const unEntity = (v) => s(v).replace(/&amp;/gi, "&").replace(/\s+/g, " ").trim();

async function buildDeploy(db, lastSync) {
  const bl = db.collection("tblBL");
  const [heads, tanks] = await Promise.all([
    bl.find({ recordType: "H", companyName: { $in: [...DEPLOY_COMPANIES, OLD_COMPANY] }, deletedNo: { $exists: false } },
      { projection: { _id: 0, companyName: 1, blId: 1, hblNo: 1, blNo: 1, hblDate: 1, blDate: 1, shipperName: 1, consigneeName: 1, plrAgentName: 1, polAgentName: 1,
                      podAgentName: 1, plrName: 1, polName: 1, podName: 1, fpdName: 1, exportJobNo: 1, cargoTypeName: 1, commodity: 1 } }).toArray(),
    bl.aggregate([
      { $match: { recordType: "D", companyName: { $in: [...DEPLOY_COMPANIES, OLD_COMPANY] }, container_containerNo: { $nin: [null, ""] }, container_deletedNo: { $exists: false } } },
      { $group: { _id: "$blId", tanks: { $addToSet: "$container_containerNo" } } },
    ]).toArray(),
  ]);
  const byBl = new Map(tanks.map((t) => [t._id, [...new Set(t.tanks.map((c) => s(c).toUpperCase()))].sort()]));
  const day = (d) => (d ? new Date(d).toISOString().slice(0, 10) : null);
  const bls = [];
  for (const h of heads) {
    const date = day(h.hblDate || h.blDate); if (!date) continue;
    if (!DEPLOY_COMPANIES.includes(h.companyName) && !(h.companyName === OLD_COMPANY && OLD_COMPANY_MONTHS.includes(date.slice(0, 7)))) continue;
    const list = byBl.get(h.blId) || [];
    bls.push({ bl: s(h.hblNo || h.blNo), date, shipper: unEntity(h.shipperName) || "(No shipper)", consignee: unEntity(h.consigneeName),
               plrAgent: unEntity(h.plrAgentName) || "(No PLR agent)", polAgent: unEntity(h.polAgentName), podAgent: unEntity(h.podAgentName),
               plr: s(h.plrName), pol: s(h.polName), pod: s(h.podName), fpd: s(h.fpdName), job: s(h.exportJobNo), cargo: s(h.cargoTypeName),
               commodity: s(h.commodity).slice(0, 120), tanks: list });
  }
  bls.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : a.bl.localeCompare(b.bl)));
  return { bls, lastSync, dataTo: bls[0]?.date || null, generatedAt: new Date().toISOString() };
}

async function deployDataset() {
  if (g._sarDeploy && Date.now() - g._sarDeploy.at < TTL_MS) return g._sarDeploy.data;
  const data = (async () => {
    const db = await getDb();
    const last = await db.collection("sarfdSyncHistory").findOne(
      { table: "tblBL", status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } },
      { sort: { startedAt: -1 }, projection: { startedAt: 1 } });
    const lastSync = last?.startedAt ? new Date(last.startedAt).toISOString() : null;
    const key = createHash("sha1").update(`${DEPLOY_SNAPSHOT_ID}|${lastSync}`).digest("hex");
    const cache = db.collection("dashboardCache");
    const snap = await cache.findOne({ _id: DEPLOY_SNAPSHOT_ID });
    if (snap?.key === key) return JSON.parse(gunzipSync(snap.gz.buffer).toString("utf8"));
    const payload = await buildDeploy(db, lastSync);
    const gz = new Binary(gzipSync(Buffer.from(JSON.stringify(payload))));
    await cache.replaceOne({ _id: DEPLOY_SNAPSHOT_ID }, { key, gz, builtAt: new Date() }, { upsert: true });
    return payload;
  })();
  g._sarDeploy = { at: Date.now(), data };
  data.catch(() => { g._sarDeploy = undefined; });
  return data;
}

// ---------------------------------------------------------------- Quotation Register
// Same columns as the Syscon "Quotation Register" report, built only from SARFD tables synced to MongoDB
// (checked against that report: every SAR Global quotation matches field for field).
//   tblRateRequest  H rows = one per quotation (dates, parties, ports, free days / detention rates, cargo, created by)
//                   C rows = charge lines  -> Buy Amount = Σ charge_buyTotalAmount, Sell Amount = Σ charge_sellTotalAmount
//                   Q rows = tank lines    -> Container Quantity = Σ qty_quantity
//   tblJob          Job No = every job whose rateRequestNo is the quotation (comma separated)

const QUOT_COMPANIES = ["SAR Global PTE Ltd"];   // plus the old company's quotations in OLD_COMPANY_MONTHS (Jan-26), as in Sales / Tank Deployment
const QUOT_SNAPSHOT_ID = "quotations-v3";
const CARGO_SHORT = { HAZARDOUS: "HAZ", GENERAL: "GEN" };

async function buildQuotations(db, lastSync) {
  const rr = db.collection("tblRateRequest");
  const match = { companyName: { $in: [...QUOT_COMPANIES, OLD_COMPANY] } };
  const [heads, money, qty] = await Promise.all([
    rr.find({ ...match, recordType: "H" }, { projection: { _id: 0, companyName: 1, rateRequestNo: 1, rateRequestDate: 1, validityTo: 1,
      originFreeDays: 1, originDemurrageFreeDays: 1, originDemurrageRate: 1, destinationFreeDays: 1, destinationDemurrageFreeDays: 1,
      destinationDemurrageRate: 1, customerName: 1, salesExecutiveName: 1, shipperName: 1, consigneeName: 1, expectedSailDate: 1,
      plrName: 1, polName: 1, podName: 1, fpdName: 1, cargoTypeName: 1, commodity: 1, noOfPackages: 1, packageName: 1, cargoWt: 1,
      createdByName: 1 } }).toArray(),
    rr.aggregate([{ $match: { ...match, recordType: "C" } },
      { $group: { _id: "$rateRequestNo", buy: { $sum: { $ifNull: ["$charge_buyTotalAmount", 0] } }, sell: { $sum: { $ifNull: ["$charge_sellTotalAmount", 0] } } } }]).toArray(),
    rr.aggregate([{ $match: { ...match, recordType: "Q" } },
      { $group: { _id: "$rateRequestNo", n: { $sum: { $ifNull: ["$qty_quantity", 0] } },
        sizes: { $addToSet: "$qty_sizeName" }, types: { $addToSet: "$qty_typeName" }, tankTypes: { $addToSet: "$qty_tankTypeName" } } }]).toArray(),
  ]);
  const nos = heads.map((h) => h.rateRequestNo);
  const jobs = await db.collection("tblJob").aggregate([
    { $match: { rateRequestNo: { $in: nos }, jobNo: { $nin: [null, ""] } } },
    { $group: { _id: "$rateRequestNo", jobs: { $addToSet: "$jobNo" } } }]).toArray();
  const byMoney = new Map(money.map((m) => [m._id, m])), byQty = new Map(qty.map((q) => [q._id, q])), byJob = new Map(jobs.map((j) => [j._id, j.jobs.sort()]));
  const day = (d) => (d ? new Date(d).toISOString().slice(0, 10) : null);
  const num = (v) => (v == null || v === "" ? null : Number(v));
  const round2 = (v) => Math.round(v * 100) / 100;
  const list = (vs) => [...new Set((vs || []).map(s).filter(Boolean))].sort().join(", ");   // container line values, e.g. "20, 40"
  const quotes = [];
  for (const h of heads) {
    const date = day(h.rateRequestDate); if (!date) continue;
    if (h.companyName === OLD_COMPANY && !OLD_COMPANY_MONTHS.includes(date.slice(0, 7))) continue;
    const m = byMoney.get(h.rateRequestNo) || { buy: 0, sell: 0 }, q = byQty.get(h.rateRequestNo) || {}, cargo = s(h.cargoTypeName);
    quotes.push({ no: s(h.rateRequestNo), date, validity: day(h.validityTo), jobs: byJob.get(h.rateRequestNo) || [],
      oFree: num(h.originFreeDays ?? h.originDemurrageFreeDays), oRate: num(h.originDemurrageRate),
      dFree: num(h.destinationFreeDays ?? h.destinationDemurrageFreeDays), dRate: num(h.destinationDemurrageRate),
      customer: unEntity(h.customerName), salesExec: unEntity(h.salesExecutiveName), shipper: unEntity(h.shipperName), consignee: unEntity(h.consigneeName),
      sailing: day(h.expectedSailDate), plr: s(h.plrName), pol: s(h.polName), pod: s(h.podName), fpd: s(h.fpdName),
      cargo: CARGO_SHORT[cargo.toUpperCase()] || cargo, commodity: s(h.commodity), packages: num(h.noOfPackages) || 0, packageType: s(h.packageName),
      grossWt: num(h.cargoWt) || 0, tanks: q.n || 0,
      tankSize: list(q.sizes), tankKind: list(q.types), tankType: list(q.tankTypes), buy: round2(m.buy), sell: round2(m.sell), profit: round2(m.sell - m.buy),
      createdBy: s(h.createdByName) });
  }
  quotes.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.no.localeCompare(a.no)));
  return { quotes, lastSync, dataTo: quotes[0]?.date || null, generatedAt: new Date().toISOString() };
}

async function quotationsDataset() {
  if (g._sarQuot && Date.now() - g._sarQuot.at < TTL_MS) return g._sarQuot.data;
  const data = (async () => {
    const db = await getDb();
    const lastOf = (table) => db.collection("sarfdSyncHistory").findOne(
      { table, status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } }, { sort: { startedAt: -1 }, projection: { startedAt: 1 } });
    const [rq, job] = await Promise.all([lastOf("tblRateRequest"), lastOf("tblJob")]);
    const iso = (x) => (x?.startedAt ? new Date(x.startedAt).toISOString() : null);
    const lastSync = iso(rq);
    const key = createHash("sha1").update(`${QUOT_SNAPSHOT_ID}|${lastSync}|${iso(job)}`).digest("hex");
    const cache = db.collection("dashboardCache");
    const snap = await cache.findOne({ _id: QUOT_SNAPSHOT_ID });
    if (snap?.key === key) return JSON.parse(gunzipSync(snap.gz.buffer).toString("utf8"));
    const payload = await buildQuotations(db, lastSync);
    const gz = new Binary(gzipSync(Buffer.from(JSON.stringify(payload))));
    await cache.replaceOne({ _id: QUOT_SNAPSHOT_ID }, { key, gz, builtAt: new Date() }, { upsert: true });
    return payload;
  })();
  g._sarQuot = { at: Date.now(), data };
  data.catch(() => { g._sarQuot = undefined; });
  return data;
}

// ---------------------------------------------------------------- Finance Recovery (AR / AP outstanding)
// Same structure as the Syscon "Invoice Outstanding" report, built from SARFD (checked invoice by invoice:
// invoice and adjusted amounts match for every open invoice SARFD holds):
//   receivable  = SAR Global sales invoices (PSI, SLI, SDI, MRI) minus receipts, credit notes and journals
//                 allocated to the invoice number (tblVoucher detail rows)
//   payable     = SAR Global purchase invoices (PI, PICI, GP, SDPI) minus payments and journals allocated to
//                 the vendor invoice number; one vendor invoice can cover several purchase invoices
//   due date    = tblInvoice.dueDate, else invoice date + credit period
//   on account  = receipts (AR) / payments (AP) and credit notes not allocated to any invoice, per party;
//                 admins can enter the figure per party until SARFD carries all receipts and payments
// Receipts and payments in SARFD lag the invoices, so recent settlements may be missing.

const FIN_COMPANIES = ["SAR Global PTE Ltd", OLD_COMPANY];   // each item is tagged co: "global" | "old"; the page filters by company
const finCo = (name) => (name === OLD_COMPANY ? "old" : "global");
const AR_VOUCHERS = ["PSI", "SLI", "SDI", "MRI"];
const AP_VOUCHERS = ["PI", "PICI", "GP", "SDPI"];
const SETTLEMENTS = ["BANK RECEIPT", "BANK PAYMENT", "JOURNAL VOUCHER", "CONTRA VOUCHER", "Principle Credit Note"];
const FIN_SNAPSHOT_ID = "finance-v4";

async function buildFinance(db, lastSync) {
  const [heads, allocs, onAcc] = await Promise.all([
    db.collection("tblInvoice").find(
      { recordType: "H", companyName: { $in: FIN_COMPANIES }, voucherCode: { $in: [...AR_VOUCHERS, ...AP_VOUCHERS] }, invoiceNo: { $not: /^PRO/i } },
      { projection: { _id: 0, companyName: 1, invoiceNo: 1, invoiceDate: 1, dueDate: 1, creditPeriod: 1, voucherCode: 1, billingPartyName: 1, vendorInvoiceNo: 1,
                      vendorInvoiceDate: 1, totalInvoiceAmount: 1, invoiceAmount: 1, currencyCode: 1, blNo: 1, jobNo: 1 } }).toArray(),
    db.collection("tblVoucher").find(
      { recordType: "D", voucherTypeName: { $in: SETTLEMENTS }, $or: [{ deletedNo: { $exists: false } }, { deletedNo: 0 }],
        $and: [{ $or: [{ detailInvoiceNo: { $nin: [null, ""] } }, { detailVendorInvoiceNo: { $nin: [null, ""] } }] }] },
      { projection: { _id: 0, detailInvoiceNo: 1, detailVendorInvoiceNo: 1, detailCreditAmount: 1, detailDebitAmount: 1 } }).toArray(),
    // money not allocated to an invoice: voucher amount less what its detail lines allocate
    db.collection("tblVoucher").aggregate([
      { $match: { companyName: { $in: FIN_COMPANIES }, voucherTypeName: { $in: ["BANK RECEIPT", "BANK PAYMENT", "Principle Credit Note"] },
                  recordType: { $in: ["H", "D"] }, $or: [{ deletedNo: { $exists: false } }, { deletedNo: 0 }, { voucherTypeName: "Principle Credit Note" }] } },
      { $group: { _id: "$voucherNo", company: { $first: "$companyName" }, type: { $first: "$voucherTypeName" }, party: { $first: "$partyName" }, date: { $first: "$voucherDate" },
                  ref: { $first: "$referenceNo" }, narration: { $first: "$narration" },
                  amount: { $max: { $cond: [{ $eq: ["$recordType", "H"] }, "$voucherAmount", 0] } },
                  allocated: { $sum: { $cond: [{ $and: [{ $eq: ["$recordType", "D"] }, { $gt: [{ $strLenCP: { $ifNull: ["$detailInvoiceNo", ""] } }, 0] }] },
                                               { $add: [{ $ifNull: ["$detailCreditAmount", 0] }, { $ifNull: ["$detailDebitAmount", 0] }] }, 0] } } } },
    ]).toArray(),
  ]);
  const key = (v) => s(v).toUpperCase();
  const settled = new Map();       // invoice / vendor invoice number -> amount settled
  for (const a of allocs) {
    const amt = (a.detailCreditAmount || 0) + (a.detailDebitAmount || 0);
    for (const k of new Set([key(a.detailInvoiceNo), key(a.detailVendorInvoiceNo)])) if (k) settled.set(k, (settled.get(k) || 0) + amt);
  }
  const day = (d) => (d ? new Date(d).toISOString().slice(0, 10) : null);
  const addDaysIso = (d, n) => { const x = new Date(d + "T00:00:00Z"); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
  const docs = [];
  // payables: settle purchase invoices sharing one vendor invoice number in date order
  const apGroups = new Map();
  for (const h of heads) {
    const date = day(h.invoiceDate); if (!date) continue;
    const ar = AR_VOUCHERS.includes(h.voucherCode);
    const amount = Math.round((h.totalInvoiceAmount ?? h.invoiceAmount ?? 0) * 100) / 100;
    const due = day(h.dueDate) || addDaysIso(date, Number(h.creditPeriod) || 0);
    const doc = { co: finCo(h.companyName), side: ar ? "ar" : "ap", party: s(h.billingPartyName) || "(No party)", invoiceNo: s(h.invoiceNo), ref: ar ? s(h.invoiceNo) : s(h.vendorInvoiceNo) || s(h.invoiceNo),
                  date, due, creditPeriod: Number(h.creditPeriod) || 0, voucher: h.voucherCode, currency: s(h.currencyCode) || "USD", amount, adjusted: 0,
                  bl: s(h.blNo), job: s(h.jobNo) };
    if (ar) { doc.adjusted = Math.min(amount, settled.get(key(h.invoiceNo)) || 0); docs.push(doc); }
    else { const k = key(h.vendorInvoiceNo) || key(h.invoiceNo); if (!apGroups.has(k)) apGroups.set(k, []); apGroups.get(k).push(doc); }
  }
  for (const [k, group] of apGroups) {
    let left = settled.get(k) || 0;
    for (const d of group.sort((a, b) => a.date.localeCompare(b.date) || a.invoiceNo.localeCompare(b.invoiceNo))) {
      d.adjusted = Math.min(d.amount, Math.max(0, left)); left -= d.adjusted; docs.push(d);
    }
  }
  const open = [];
  for (const d of docs) {
    const out = Math.round((d.amount - d.adjusted) * 100) / 100;
    if (Math.abs(out) < 0.01) continue;
    d.adjusted = Math.round(d.adjusted * 100) / 100;
    d.outstanding = d.side === "ap" ? -out : out;     // payables negative, as in the Syscon report
    open.push(d);
  }
  open.sort((a, b) => a.party.localeCompare(b.party) || a.date.localeCompare(b.date));
  // on account per party: receipts and credit notes reduce receivables; payments reduce payables
  const onAccount = { ar: {}, ap: {} }, onAccountOld = { ar: {}, ap: {} }, onAccountDocs = [];   // SAR Global / old company
  for (const v of onAcc) {
    const left = Math.round(((v.amount || 0) - (v.allocated || 0)) * 100) / 100;
    if (left < 0.01 || !s(v.party)) continue;
    const side = v.type === "BANK PAYMENT" ? "ap" : "ar", co = finCo(v.company), bucket = co === "old" ? onAccountOld : onAccount;
    bucket[side][s(v.party)] = Math.round(((bucket[side][s(v.party)] || 0) + left) * 100) / 100;
    onAccountDocs.push({ co, side, party: s(v.party), voucherNo: s(v._id), type: s(v.type), date: day(v.date), ref: s(v.ref), narration: s(v.narration).slice(0, 160),
                         amount: Math.round((v.amount || 0) * 100) / 100, allocated: Math.round((v.allocated || 0) * 100) / 100, onAccount: left });
  }
  const dataTo = heads.reduce((mx, h) => { const d = day(h.invoiceDate); return d && d > mx ? d : mx; }, "");
  return { docs: open, onAccount, onAccountOld, onAccountDocs, lastSync, dataTo: dataTo || null, generatedAt: new Date().toISOString() };
}

async function financeDataset() {
  if (g._sarFin && Date.now() - g._sarFin.at < TTL_MS) return g._sarFin.data;
  const data = (async () => {
    const db = await getDb();
    const syncs = await Promise.all(["tblInvoice", "tblVoucher"].map((table) => db.collection("sarfdSyncHistory").findOne(
      { table, status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } }, { sort: { startedAt: -1 }, projection: { startedAt: 1 } })));
    const times = syncs.map((x) => (x?.startedAt ? new Date(x.startedAt).toISOString() : null));
    const lastSync = times.filter(Boolean).sort().pop() || null;
    const key = createHash("sha1").update(`${FIN_SNAPSHOT_ID}|${times.join("|")}`).digest("hex");
    const cache = db.collection("dashboardCache");
    const snap = await cache.findOne({ _id: FIN_SNAPSHOT_ID });
    if (snap?.key === key) return JSON.parse(gunzipSync(snap.gz.buffer).toString("utf8"));
    const payload = await buildFinance(db, lastSync);
    const gz = new Binary(gzipSync(Buffer.from(JSON.stringify(payload))));
    await cache.replaceOne({ _id: FIN_SNAPSHOT_ID }, { key, gz, builtAt: new Date() }, { upsert: true });
    return payload;
  })();
  g._sarFin = { at: Date.now(), data };
  data.catch(() => { g._sarFin = undefined; });
  return data;
}

// Remarks per party ("Will settle in SOA" ...), typed by admins; one per side + party.
async function financeRemarks() {
  const db = await getDb();
  return db.collection("financeRemarks").find({}, { projection: { _id: 0 } }).toArray();
}
async function saveFinanceRemark(body, user) {
  requireAdmin(user);
  const side = body.side === "ap" ? "ap" : body.side === "ar" ? "ar" : null;
  const party = s(body.party);
  if (!side || !party) throw new HttpError(400, "side and party are required");
  const db = await getDb(), col = db.collection("financeRemarks");
  const id = `${side}|${party.toUpperCase()}`;
  const set = { side, party, updatedAt: new Date(), updatedBy: user.email }, unset = {};
  if ("remark" in body) { const r = s(body.remark).slice(0, 500); if (r) set.remark = r; else unset.remark = ""; }
  if ("onAccount" in body) {
    if (body.onAccount === null || body.onAccount === "") { unset.onAccount = ""; unset.onAccountAt = ""; unset.onAccountBy = ""; }
    else {
      const n = Number(body.onAccount);
      if (!Number.isFinite(n) || Math.abs(n) > 1e9) throw new HttpError(400, "onAccount must be a number");
      Object.assign(set, { onAccount: Math.round(Math.abs(n) * 100) / 100, onAccountAt: new Date(), onAccountBy: user.email });
    }
  }
  const update = { $set: set, ...(Object.keys(unset).length ? { $unset: unset } : {}) };
  if ("onAccount" in body) {   // keep the last 50 changes for the On Account detail view
    const before = await col.findOne({ _id: id }, { projection: { onAccount: 1, onAccountAt: 1, onAccountBy: 1, onAccountLog: 1 } });
    const entries = [];
    if (before?.onAccount != null && !before.onAccountLog?.length)   // figure entered before history was kept
      entries.push({ amount: before.onAccount, at: before.onAccountAt || null, by: before.onAccountBy || "" });
    entries.push({ amount: set.onAccount ?? null, at: new Date(), by: user.email });
    update.$push = { onAccountLog: { $each: entries, $slice: -50 } };
  }
  await col.updateOne({ _id: id }, update, { upsert: true });
  const doc = await col.findOne({ _id: id });
  if (!doc.remark && doc.onAccount == null) await col.deleteOne({ _id: id });   // nothing left to keep
  return financeRemarks();
}

// ---------------------------------------------------------------- user management (admins)

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLES = ["admin", "viewer"];

function requireAdmin(user) {
  if (user.role !== "admin") throw new HttpError(403, "Only admins can do this", "admin_only");
}

async function listUsers() {
  const db = await getDb();
  const docs = await db.collection("dashboardUsers")
    .find({}, { projection: { _id: 0, email: 1, name: 1, role: 1, disabled: 1, addedAt: 1, addedBy: 1, updatedAt: 1, updatedBy: 1 } })
    .sort({ email: 1 }).toArray();
  const users = docs.map((d) => ({ ...d, role: d.role === "admin" ? "admin" : "viewer", disabled: !!d.disabled }));
  for (const e of list(process.env.ADMIN_EMAILS)) {   // env admins can't be edited here
    const u = users.find((x) => x.email === e);
    if (u) Object.assign(u, { role: "admin", locked: true }); else users.push({ email: e, role: "admin", disabled: false, locked: true });
  }
  return users;
}

async function saveUser(body, user) {
  requireAdmin(user);
  const email = String(body.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email)) throw new HttpError(400, "Enter a valid email address");
  const role = body.role ?? "viewer";
  if (!ROLES.includes(role)) throw new HttpError(400, "Role must be admin or viewer");
  const disabled = !!body.disabled;
  const name = body.name === undefined ? undefined : String(body.name).trim().slice(0, 100);
  if (email === user.email && (role !== "admin" || disabled)) throw new HttpError(400, "You can't remove your own admin access");
  if (list(process.env.ADMIN_EMAILS).includes(email)) throw new HttpError(400, `${email} is set in ADMIN_EMAILS and can only be changed in Vercel`);

  const db = await getDb();
  const users = db.collection("dashboardUsers");
  if (body.create && await users.findOne({ email }, { projection: { _id: 1 } })) {
    throw new HttpError(409, `${email} already has access`);
  }
  const now = new Date();
  await users.updateOne(
    { email },
    { $set: { role, disabled, ...(name !== undefined && { name }), updatedAt: now, updatedBy: user.email },
      $setOnInsert: { email, addedAt: now, addedBy: user.email } },
    { upsert: true },
  );
  return listUsers();
}

/** Import: add new users and update name/role of existing ones. Rows that would lock you out are skipped. */
async function bulkSaveUsers(body, user) {
  requireAdmin(user);
  const rows = Array.isArray(body.users) ? body.users : [];
  if (!rows.length) throw new HttpError(400, "No users to import");
  if (rows.length > 1000) throw new HttpError(400, "At most 1000 users per import");
  const db = await getDb();
  const users = db.collection("dashboardUsers");
  const envAdmins = list(process.env.ADMIN_EMAILS);
  const existing = new Map((await users.find({}, { projection: { _id: 0, email: 1, name: 1, role: 1 } }).toArray()).map((u) => [u.email, u]));
  const result = { added: 0, updated: 0, unchanged: 0, skipped: [] };
  const now = new Date(), seen = new Set();
  for (const r of rows) {
    const email = String(r?.email || "").trim().toLowerCase();
    const name = String(r?.name || "").trim().slice(0, 100);
    const role = String(r?.role || "").trim().toLowerCase();
    const skip = (reason) => result.skipped.push({ email: email || String(r?.email || ""), reason });
    if (!EMAIL_RE.test(email)) { skip("Invalid email"); continue; }
    if (!ROLES.includes(role)) { skip(`Unknown role "${r?.role ?? ""}"`); continue; }
    if (seen.has(email)) { skip("Duplicate in file"); continue; }
    seen.add(email);
    if (envAdmins.includes(email)) { skip("Set in ADMIN_EMAILS"); continue; }
    if (email === user.email && role !== "admin") { skip("Can't remove your own admin access"); continue; }
    const cur = existing.get(email);
    if (cur && (cur.role === "admin" ? "admin" : "viewer") === role && (!name || cur.name === name)) { result.unchanged++; continue; }
    await users.updateOne(
      { email },
      { $set: { role, ...(name && { name }), updatedAt: now, updatedBy: user.email },
        $setOnInsert: { email, disabled: false, addedAt: now, addedBy: user.email } },
      { upsert: true },
    );
    cur ? result.updated++ : result.added++;
  }
  return { ...result, users: await listUsers() };
}

async function deleteUser(body, user) {
  requireAdmin(user);
  const email = String(body.email || "").trim().toLowerCase();
  if (email === user.email) throw new HttpError(400, "You can't remove yourself");
  if (list(process.env.ADMIN_EMAILS).includes(email)) throw new HttpError(400, `${email} is set in ADMIN_EMAILS and can only be changed in Vercel`);
  const db = await getDb();
  const { deletedCount } = await db.collection("dashboardUsers").deleteOne({ email });
  if (!deletedCount) throw new HttpError(404, `${email} was not found`);
  return listUsers();
}

// ---------------------------------------------------------------- usage analytics
// One document per sign-in in dashboardLogins: { email, name, at }.

const USAGE_TZ = "Asia/Kolkata";
const USAGE_DAYS = 30;
let loginIndexReady = false;

async function recordLogin(user) {
  const db = await getDb();
  const logins = db.collection("dashboardLogins");
  if (!loginIndexReady) { await logins.createIndex({ at: -1 }).catch(() => {}); loginIndexReady = true; }
  await logins.insertOne({ email: user.email, name: user.name, at: new Date() });
}

async function usageAnalytics(user) {
  requireAdmin(user);
  const db = await getDb();
  const logins = db.collection("dashboardLogins");
  const now = Date.now(), day = 86400000;
  const since = new Date(now - USAGE_DAYS * day);
  const [listed, perUser, perDay] = await Promise.all([
    listUsers(),
    logins.aggregate([
      { $group: { _id: "$email", name: { $last: "$name" }, totalLogins: { $sum: 1 }, lastLogin: { $max: "$at" },
                  logins30: { $sum: { $cond: [{ $gte: ["$at", since] }, 1, 0] } } } },
    ]).toArray(),
    logins.aggregate([
      { $match: { at: { $gte: since } } },
      { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$at", timezone: USAGE_TZ } },
                  logins: { $sum: 1 }, users: { $addToSet: "$email" } } },
    ]).toArray(),
  ]);

  const stats = new Map(perUser.map((d) => [d._id, d]));
  const users = listed.map((u) => {
    const st = stats.get(u.email); stats.delete(u.email);
    return { email: u.email, name: u.name || st?.name || "", role: u.role, disabled: u.disabled,
             totalLogins: st?.totalLogins || 0, logins30: st?.logins30 || 0, lastLogin: st?.lastLogin || null };
  });
  // people who signed in through ALLOWED_DOMAINS or were removed since
  for (const st of stats.values()) {
    users.push({ email: st._id, name: st.name || "", role: "viewer", disabled: false, notListed: true,
                 totalLogins: st.totalLogins, logins30: st.logins30, lastLogin: st.lastLogin });
  }
  users.sort((a, b) => (b.lastLogin ? +new Date(b.lastLogin) : 0) - (a.lastLogin ? +new Date(a.lastLogin) : 0) || a.email.localeCompare(b.email));

  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: USAGE_TZ, year: "numeric", month: "2-digit", day: "2-digit" });
  const byDay = new Map(perDay.map((d) => [d._id, d]));
  const daily = [];
  for (let i = USAGE_DAYS - 1; i >= 0; i--) {
    const key = fmt.format(new Date(now - i * day));
    daily.push({ date: key, logins: byDay.get(key)?.logins || 0, users: byDay.get(key)?.users.length || 0 });
  }

  const week = now - 7 * day;
  return {
    totalUsers: users.filter((u) => !u.notListed).length,
    activeUsers: users.filter((u) => !u.notListed && !u.disabled).length,
    loggedInLast7Days: users.filter((u) => u.lastLogin && +new Date(u.lastLogin) >= week).length,
    logins30: daily.reduce((n, d) => n + d.logins, 0),
    days: USAGE_DAYS, timezone: USAGE_TZ, daily, users,
  };
}

// ---------------------------------------------------------------- request handling

/** Runs one request ({ dataset } or { collection, pipeline }) for a signed-in user. */
export async function runRequest(body, user) {
  if (!body || typeof body !== "object") throw new HttpError(400, "Request body must be JSON");
  if (body.dataset === "sales") return salesDataset();
  if (body.dataset === "mr") return mrDataset();
  if (body.dataset === "deploy") return deployDataset();
  if (body.dataset === "quotations") return quotationsDataset();
  if (body.dataset === "finance") return financeDataset();
  if (body.dataset === "financeRemarks") return financeRemarks();
  if (body.action === "saveFinanceRemark") return saveFinanceRemark(body, user);
  if (body.dataset === "me") { if (body.login === true) await recordLogin(user).catch((e) => console.error(e)); return user; }
  if (body.dataset === "users") { requireAdmin(user); return listUsers(); }
  if (body.dataset === "usage") return usageAnalytics(user);
  if (body.action === "saveUser") return saveUser(body, user);
  if (body.action === "deleteUser") return deleteUser(body, user);
  if (body.action === "bulkSaveUsers") return bulkSaveUsers(body, user);
  if (body.action) throw new HttpError(400, `Unknown action ${body.action}`);
  if (body.dataset) throw new HttpError(400, `Unknown dataset ${body.dataset}`);
  return aggregate(body.collection, body.pipeline);
}

export function parseBody(req) {
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch { throw new HttpError(400, "Invalid JSON"); } }
  return req.body;
}

export function sendError(res, e) {
  const status = e instanceof HttpError ? e.status : 500;
  if (status === 500) console.error(e);
  res.status(status).json({ error: status === 500 && !(e instanceof HttpError) ? "Server error" : e.message, code: e.code });
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  try {
    if (req.method === "GET" && req.query?.config !== undefined) {
      return res.status(200).json({ googleClientId: GOOGLE_CLIENT_ID });
    }
    if (req.method !== "POST") throw new HttpError(405, "Use POST");
    const user = await authenticate(req);
    res.status(200).json(await runRequest(parseBody(req), user));
  } catch (e) {
    sendError(res, e);
  }
}
