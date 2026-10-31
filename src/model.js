// OpenRouter client. Picks models from env.MODELS (comma-separated) or, if unset,
// discovers currently-free chat models from OpenRouter's public model list.

const API = "https://openrouter.ai/api/v1";
const PREFER = [/llama-3\.3-70b/i, /gpt-oss/i, /qwen3?.*(235b|72b|32b|30b)/i, /deepseek.*(chat|v3)/i, /gemini/i, /mistral/i, /glm/i, /kimi/i];
const AVOID = /r1|thinking|reason|vision|-vl|image|embed|guard|safeguard|audio|coder|lite|tiny|1b|3b|7b|8b/i;

let discovered = { at: 0, ids: [] };

async function discoverFree(signal) {
  if (Date.now() - discovered.at < 3600_000 && discovered.ids.length) return discovered.ids;
  const res = await fetch(`${API}/models`, { signal });
  if (!res.ok) throw new Error("model list " + res.status);
  const j = await res.json();
  const free = (j.data || []).filter(
    (m) =>
      m.id &&
      /:free$/.test(m.id) &&
      Number(m.pricing?.prompt) === 0 &&
      Number(m.pricing?.completion) === 0 &&
      (m.context_length || 0) >= 32000 &&
      !AVOID.test(m.id),
  );
  const score = (m) => {
    const i = PREFER.findIndex((re) => re.test(m.id));
    return (i < 0 ? 99 : i) * 1e7 - (m.context_length || 0);
  };
  free.sort((a, b) => score(a) - score(b));
  discovered = { at: Date.now(), ids: free.map((m) => m.id).slice(0, 8) };
  return discovered.ids;
}

export function makeModelCaller(env) {
  return async function callModel(messages, { attempt = 0, salt = 0, timeoutMs = 24000 } = {}) {
    if (!env.OPENROUTER_API_KEY) throw new Error("OPENROUTER_API_KEY not set");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.max(1000, timeoutMs));
    try {
      let ids = (env.MODELS || "").split(",").map((s) => s.trim()).filter(Boolean);
      if (!ids.length) ids = await discoverFree(ctrl.signal);
      if (!ids.length) throw new Error("no models available");
      const model = ids[(salt + attempt) % ids.length];
      const res = await fetch(`${API}/chat/completions`, {
        method: "POST",
        signal: ctrl.signal,
        headers: {
          Authorization: `Bearer ${env.OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://mailroom-agent.invalid",
          "X-Title": "mailroom-agent",
        },
        body: JSON.stringify({ model, messages, temperature: 0, max_tokens: 3500 }),
      });
      if (!res.ok) throw new Error(`openrouter ${res.status}`);
      const j = await res.json();
      const text = j?.choices?.[0]?.message?.content;
      if (typeof text !== "string" || !text.trim()) throw new Error("empty completion");
      return text;
    } finally {
      clearTimeout(timer);
    }
  };
}
