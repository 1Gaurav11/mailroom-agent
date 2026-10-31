import pg from "pg";

// Durable key/value store on Postgres (jsonb). Same {get, put} interface the core expects.
export async function makePgStore(url) {
  const host = new URL(url).hostname;
  // Render's internal DB hostname has no dots; the external one does and requires TLS.
  const ssl = process.env.PGSSL === "off" ? false : host.includes(".") ? { rejectUnauthorized: false } : false;
  const pool = new pg.Pool({ connectionString: url, ssl, max: 5, connectionTimeoutMillis: 10000 });
  await pool.query("create table if not exists kv (k text primary key, v jsonb not null)");
  return {
    async get(k) {
      const r = await pool.query("select v from kv where k = $1", [k]);
      return r.rows[0]?.v;
    },
    async put(k, v) {
      await pool.query(
        "insert into kv (k, v) values ($1, $2::jsonb) on conflict (k) do update set v = excluded.v",
        [k, JSON.stringify(v)],
      );
    },
  };
}
