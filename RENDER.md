# Deploy on Render (instead of Cloudflare)

State lives in Postgres (table `kv`), created automatically on first start.

## Steps
1. Put this folder in a GitHub repo (do not commit `node_modules`; add a `.gitignore` with `node_modules`).
2. Render dashboard → New → Blueprint → pick the repo. It reads `render.yaml` and creates the
   web service `mailroom-agent` plus the Postgres database `mailroom-db`, and links `DATABASE_URL` for you.
3. When prompted, enter `OPENROUTER_API_KEY` (a secret; never put it in code).
4. After the first deploy your URL is `https://mailroom-agent-XXXX.onrender.com`. Submit exactly that
   (no path needed, no query, no fragment).
5. Smoke test: open the URL in a browser; you should see `{"ok":true,...}`.

No GitHub? New → Web Service → "Public Git repository" or upload via a Git host; or use the Render CLI.
Manual setup values: runtime Node, build `npm install --omit=dev`, start `node src/server.js`,
env vars `OPENROUTER_API_KEY` and `DATABASE_URL` (Internal Database URL of a Render Postgres in the same region).

## Free-tier caveats (important for the exam)
- A free web service sleeps after ~15 minutes idle and takes up to about a minute to wake. The grader's first
  request has a 55 s limit, so WAKE IT FIRST: open the URL in a browser, wait for `{"ok":true}`, then press Check.
  The paid Starter instance ($7/mo) never sleeps and is the safe choice for Save.
- Free Postgres is deleted after 30 days, which is fine for the exam window.
- Do not let two Check runs overlap with a cold start; wait for the response before pressing again.
