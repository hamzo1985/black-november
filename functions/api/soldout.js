// الأصناف الخلصانة: الموقع بيقرأ (GET)، وصفحة /admin بتعدّل بالرمز (POST).
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const MAX_FAILS = 8, LOCK_MS = 15 * 60 * 1000;

async function outKeys(db) {
  const { results } = await db.prepare("SELECT key FROM soldout").all();
  return results.map(r => r.key);
}
async function samePin(a, b) {
  const h = async s => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  const [x, y] = await Promise.all([h(a), h(b)]);
  return x.reduce((d, v, i) => d | (v ^ y[i]), 0) === 0;
}

export async function onRequestGet({ env }) {
  if (!env.DB) return json({ out: [] });
  try { return json({ out: await outKeys(env.DB) }); }
  catch (e) { return json({ out: [] }); }   // عطل هون ما بيوقف الموقع
}

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.ADMIN_PIN) return json({ error: "not_configured" }, 503);
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad_request" }, 400); }
  const ip = request.headers.get("CF-Connecting-IP") || "local", now = Date.now();
  const f = await env.DB.prepare("SELECT n, until FROM fails WHERE ip = ?").bind(ip).first();
  if (f && f.until > now) return json({ error: "locked" }, 429);
  if (!(await samePin(String(b.pin || ""), env.ADMIN_PIN))) {
    const n = f && f.n < MAX_FAILS ? f.n + 1 : 1;
    await env.DB.prepare("INSERT OR REPLACE INTO fails (ip, n, until) VALUES (?, ?, ?)").bind(ip, n, n >= MAX_FAILS ? now + LOCK_MS : 0).run();
    return json({ error: "wrong_pin" }, 401);
  }
  if (f) await env.DB.prepare("DELETE FROM fails WHERE ip = ?").bind(ip).run();

  if (b.action === "log") {
    const { results } = await env.DB.prepare("SELECT key, out, at, who FROM log ORDER BY id DESC LIMIT 100").all();
    return json({ out: await outKeys(env.DB), log: results });
  }
  if (b.action === "set") {
    const key = String(b.key || ""), who = String(b.who || "").trim().slice(0, 40);
    if (!/^[pwh]:[\w.-]{1,60}$/.test(key) || !who) return json({ error: "bad_request" }, 400);
    const at = new Date(now).toISOString(), out = !!b.out;
    await env.DB.batch([
      out ? env.DB.prepare("INSERT OR REPLACE INTO soldout (key, at, who) VALUES (?, ?, ?)").bind(key, at, who)
          : env.DB.prepare("DELETE FROM soldout WHERE key = ?").bind(key),
      env.DB.prepare("INSERT INTO log (key, out, at, who) VALUES (?, ?, ?, ?)").bind(key, out ? 1 : 0, at, who),
    ]);
  }
  return json({ out: await outKeys(env.DB) });
}
