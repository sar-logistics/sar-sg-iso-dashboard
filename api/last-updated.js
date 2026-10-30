// GET /api/last-updated → { lastUpdated: ISO string | null }
// When fresh data last arrived in this dashboard's database: the latest successful SARFD table load
// that inserted rows (sarfd_sync.py logs every load in sarfdSyncHistory; the dashboard's own
// "Last sync" lines use the same rule per data set). Read by the SAR Systems Hub for the
// "Updated …" line on this dashboard's card. Returns a single timestamp, no data, so it needs no
// sign-in.

import { MongoClient } from "mongodb";

const DB_NAME = process.env.MONGODB_DB || "sar_iso_dashboard";

const g = globalThis;
async function getDb() {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is not set");
  if (!g._sarMongo) {
    g._sarMongo = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 8000, maxPoolSize: 2 }).connect();
    g._sarMongo.catch(() => { g._sarMongo = undefined; });
  }
  return (await g._sarMongo).db(DB_NAME);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  try {
    const db = await getDb();
    const latest = await db.collection("sarfdSyncHistory").findOne(
      { status: { $in: ["success", "warning"] }, rowsInserted: { $gt: 0 } },
      { sort: { startedAt: -1 }, projection: { _id: 0, startedAt: 1 } },
    );
    const time = latest && latest.startedAt ? new Date(latest.startedAt) : null;
    return res.status(200).json({ lastUpdated: time && !isNaN(time.getTime()) ? time.toISOString() : null });
  } catch (err) {
    console.error("last-updated:", err.message);
    return res.status(500).json({ lastUpdated: null });
  }
}
