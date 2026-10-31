import { DurableObject } from "cloudflare:workers";
import { createHandler } from "./core.js";
import { makeModelCaller } from "./model.js";

const MAX_BODY = 4 * 1024 * 1024;
const JSON_HEADERS = { "Content-Type": "application/json", "Cache-Control": "no-store" };
const json = (status, obj) => new Response(JSON.stringify(obj), { status, headers: JSON_HEADERS });

// One Durable Object holds all durable state (decisions, evaluations, receipts)
// and serializes work per evaluationId.
export class MailroomStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    const store = {
      get: (k) => ctx.storage.get(k),
      put: (k, v) => ctx.storage.put(k, v),
    };
    this.handler = createHandler({
      store,
      callModel: makeModelCaller(env),
      cfg: {
        chunkSize: Number(env.CHUNK_SIZE) || 8,
        concurrency: Number(env.CONCURRENCY) || 4,
      },
    });
  }

  async fetch(request) {
    const text = await request.text();
    const out = await this.handler.handle(text);
    return new Response(out.body, { status: out.status, headers: JSON_HEADERS });
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "GET") return json(200, { ok: true, service: "mailroom-agent" });
    if (request.method !== "POST") return json(405, { error: "method_not_allowed", message: "use POST" });
    const len = Number(request.headers.get("content-length") || 0);
    if (len > MAX_BODY) return json(413, { error: "body_too_large", message: "request body too large" });
    const text = await request.text();
    if (text.length > MAX_BODY) return json(413, { error: "body_too_large", message: "request body too large" });
    const stub = env.STORE.get(env.STORE.idFromName("main"));
    return stub.fetch(new Request("https://do/", { method: "POST", body: text }));
  },
};
