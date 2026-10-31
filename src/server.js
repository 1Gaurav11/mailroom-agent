import http from "node:http";
import { createHandler } from "./core.js";
import { makeModelCaller } from "./model.js";

const MAX_BODY = 4 * 1024 * 1024;
const HEADERS = { "Content-Type": "application/json", "Cache-Control": "no-store" };

let store;
if (process.env.DATABASE_URL) {
  const { makePgStore } = await import("./pgstore.js");
  store = await makePgStore(process.env.DATABASE_URL);
  console.log("state: postgres");
} else {
  // Local testing only: NOT durable. Render must have DATABASE_URL set.
  const m = new Map();
  store = { get: async (k) => (m.has(k) ? structuredClone(m.get(k)) : undefined), put: async (k, v) => void m.set(k, structuredClone(v)) };
  console.warn("WARNING: DATABASE_URL not set, using in-memory state (not durable)");
}

const handler = createHandler({
  store,
  callModel: makeModelCaller(process.env),
  cfg: {
    chunkSize: Number(process.env.CHUNK_SIZE) || 8,
    concurrency: Number(process.env.CONCURRENCY) || 4,
  },
});

const send = (res, status, body) => {
  res.writeHead(status, HEADERS);
  res.end(typeof body === "string" ? body : JSON.stringify(body));
};

http
  .createServer((req, res) => {
    if (req.method === "GET") return send(res, 200, { ok: true, service: "mailroom-agent" });
    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed", message: "use POST" });
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", async () => {
      if (tooBig) return send(res, 413, { error: "body_too_large", message: "request body too large" });
      try {
        const out = await handler.handle(Buffer.concat(chunks).toString("utf8"));
        send(res, out.status, out.body);
      } catch (e) {
        console.error("handler error", e);
        send(res, 500, { error: "internal_error", message: "internal error" });
      }
    });
    req.on("error", () => send(res, 400, { error: "bad_request", message: "request error" }));
  })
  .listen(Number(process.env.PORT) || 10000, "0.0.0.0", () => console.log("listening"));
