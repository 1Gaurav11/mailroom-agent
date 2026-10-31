# Mailroom action gate (Cloudflare Worker)

Public HTTPS endpoint for the "Safe AI Mailroom" exam (`ga5-mailroom-action-gate/v2`).

- `src/core.js`: canonical hashing, validation, AI decision step, code-side guards, persistence, receipt verification
- `src/model.js`: OpenRouter client (auto-discovers free models unless `MODELS` is set)
- `src/worker.js`: Worker entry plus a Durable Object (SQLite-backed) holding all durable state
- `test/local.test.mjs`: replay, 409, malformed input, caching, signatures; the model is mocked, so no checks are spent

## Test locally (no model, no network)

    npm test

## Deploy

    npm install
    npx wrangler login
    npx wrangler secret put OPENROUTER_API_KEY     # paste your key; never put it in code or prompts
    npx wrangler deploy

Wrangler prints `https://mailroom-agent.<your-subdomain>.workers.dev`. Submit that URL
(no query, no fragment, no credentials). The Worker accepts POST on any path.

Smoke test (should be a 422 JSON error, which proves it is live and validating):

    curl -s -X POST https://mailroom-agent.<sub>.workers.dev -d '{"profile":"ga5-mailroom-action-gate/v2","operation":"propose","evaluationId":"x"}'

## Choosing models

By default the Worker asks OpenRouter for its current free models and picks capable ones with >= 32k context.
For more reliable results, pin them in `wrangler.toml`:

    MODELS = "meta-llama/llama-3.3-70b-instruct:free,openai/gpt-oss-120b:free"

Check openrouter.ai/models (filter: free) for ids that exist today. Models are rotated per chunk and per retry.
Free OpenRouter accounts have a small daily request cap; if you hit it, adding a few dollars of credit lifts it a lot.
The first 58 core dossiers need about 8 to 10 model calls; after that everything is served from cache.

## How checks are best spent (10 total, last one reserved for Save)

1. First Check is the warm-up. If the model is slow or rate-limited, some core cases fall back to a safe
   `quarantine_item` for that run only. Fallbacks are NOT cached, so the next Check re-asks the model for just those.
2. Read the feedback layer by layer. Contract / receipt / replay layers should pass immediately (they are
   covered by the local tests). Remaining misses are decision quality: tune `SYSTEM_PROMPT` in `src/core.js`.
3. Decisions are cached by dossier content, so after a prompt change the old cached decisions would still be served.
   To re-decide, bump the cache version in `resolveDecisions` (prefix `dec:`, e.g. `dec2:`) and redeploy.
4. Before Save, run one Check that comes back clean and consistent.

## Behaviour summary

- 400: bad JSON, wrong profile, unknown operation. 422: schema errors, duplicate dossierId, bad verifier key
  (all before any model work). 409: same evaluationId with different content. 404: commit for unknown evaluation.
  422 on commit: signature invalid/moved, receipt not matching call ID, action or proposal digest, missing or extra receipts.
  Exact replays return the stored bytes and do no model work or effects.
- The model chooses only an action, evidence line IDs, and argument values. Code builds the exact target and payload
  and rejects any argument not copied from the dossier, anything resembling canary/vault/secret strings, and any
  `send_approved_notice` whose recipient/reference/status is not in the cited lines. Failures trigger one repair
  attempt, then a safe quarantine fallback. Nothing outbound is ever the fallback.
- No tool is actually executed: `executed` just means a verified receipt had `accepted: true`.

## Known assumptions

- Canonical JSON follows JavaScript `JSON.stringify` spelling (non-ASCII is emitted raw, not `\uXXXX`).
- Arguments are matched case-insensitively against dossier text, then snapped to the dossier's own casing.
- `owningTeam` is the only argument not required to appear verbatim (it may be a queue name implied by policy).
