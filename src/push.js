// Notifiche sul telefono (Web Push): cifratura RFC 8291 e firma VAPID RFC 8292, senza librerie esterne.
// Le chiavi VAPID si creano da sole al primo utilizzo e restano nel database (tabella push_keys, mai esportata).
const enc = new TextEncoder();
const SITE = 'https://scadenziario.andreaagamennone93.workers.dev';
const MAX_SUBS = 40;          // limite di telefoni registrati (il piano gratuito concede 50 richieste per esecuzione)
const SEND_HOUR = 7;          // ora italiana dell'avviso del mattino (le due esecuzioni in wrangler.jsonc coprono ora legale e solare)
const OK_HOST = /^(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|web\.push\.apple\.com|[a-z0-9.-]+\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com)$/;

export const b64u = (buf) => {
  const a = new Uint8Array(buf); let s = '';
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
export const unb64u = (s) => {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
};
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

/* ---------- database ---------- */
let ready = false;
async function schema(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS push_keys (id INTEGER PRIMARY KEY CHECK (id = 1), pub TEXT NOT NULL, priv TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS push_subs (endpoint TEXT PRIMARY KEY, p256dh TEXT NOT NULL, auth TEXT NOT NULL, depts TEXT NOT NULL, who TEXT, admin INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)')
  ]);
  ready = true;
}
async function vapid(env) {
  await schema(env);
  const q = () => env.DB.prepare('SELECT pub, priv FROM push_keys WHERE id = 1').first();
  let r = await q();
  if (!r) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
    const priv = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
    await env.DB.prepare('INSERT OR IGNORE INTO push_keys (id, pub, priv) VALUES (1, ?, ?)').bind(pub, priv).run();
    r = await q();
  }
  return r;
}

/* ---------- crittografia ---------- */
export async function makeJwt(privJwk, aud, nowSec) {
  const key = await crypto.subtle.importKey('jwk', JSON.parse(privJwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: nowSec + 12 * 3600, sub: SITE })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body));
  return head + '.' + body + '.' + b64u(sig);
}
const hkdf = async (salt, ikm, info, len) => {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
};
export async function encrypt(p256dh, authKey, text) {
  const uaPub = unb64u(p256dh), auth = unb64u(authKey);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode('WebPush: info\x00'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\x00'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\x00'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(enc.encode(text), new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct);   // intestazione: sale, record 4096, lunghezza chiave, chiave
}

/* ---------- invio ---------- */
async function sendOne(v, jwts, sub, payload) {
  const origin = new URL(sub.endpoint).origin;
  if (!jwts[origin]) jwts[origin] = await makeJwt(v.priv, origin, Math.floor(Date.now() / 1000));
  const body = await encrypt(sub.p256dh, sub.auth, JSON.stringify(payload));
  try {
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '43200', Urgency: 'normal',
        Authorization: 'vapid t=' + jwts[origin] + ', k=' + v.pub
      },
      body
    });
    return res.status;
  } catch (e) { return 0; }
}

/* ---------- calcolo delle scadenze (stesse regole dell'app: vince la data piu' vicina) ---------- */
const dayNum = (s) => { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s || ''); return m ? Date.UTC(+m[1], +m[2] - 1, +m[3]) / 864e5 : null; };
export function deadlineDay(scad, aperto, durata) {
  const c = [];
  const s = dayNum(scad); if (s != null) c.push(s);
  const a = dayNum(aperto);
  if (a != null && Number(durata) > 0) c.push(a + Math.floor(Number(durata)));
  return c.length ? Math.min(...c) : null;
}
export function buildLines(rows, today, urgentDays, soonDays, depts) {
  const t = dayNum(today), lines = [];
  for (const d of depts) {
    let over = 0, urg = 0, soon = 0;
    for (const r of rows) {
      if (r.dept !== d) continue;
      const dl = deadlineDay(r.scad, r.aperto, r.durata);
      if (dl == null) continue;
      const left = dl - t;
      if (left < 0) over++; else if (left <= urgentDays) urg++; else if (left <= soonDays) soon++;
    }
    const p = [];
    if (over) p.push(over + (over === 1 ? ' scaduto' : ' scaduti'));
    if (urg) p.push(urg + (urg === 1 ? ' urgente' : ' urgenti'));
    if (soon) p.push(soon + ' in scadenza');
    if (p.length) lines.push(d + ': ' + p.join(', '));
  }
  return lines;
}

async function collect(env, subs) {
  const need = new Set(); subs.forEach(s => JSON.parse(s.depts).forEach(d => need.add(d)));
  const set = Object.fromEntries((await env.DB.prepare("SELECT k, v FROM settings WHERE k IN ('urgentDays','soonDays')").all()).results.map(r => [r.k, Number(r.v)]));
  const op = (await env.DB.prepare("SELECT dept, scad, aperto, durata FROM openings WHERE stato = 'aperto'").all()).results;
  const ar = (await env.DB.prepare("SELECT dept, scad, '' AS aperto, NULL AS durata FROM arrivals WHERE stato = 'giacenza'").all()).results;
  return { rows: op.concat(ar), urgent: set.urgentDays ?? 1, soon: set.soonDays ?? 3 };
}

// Avviso del mattino. Con only = indirizzo di un telefono, manda subito solo a quello (prova), anche se non c'e' nulla.
export async function runDaily(env, nowLocal, only) {
  await schema(env);
  if (!only && Number(nowLocal.slice(11, 13)) !== SEND_HOUR) return 'fuori orario';
  const subs = only
    ? (await env.DB.prepare('SELECT * FROM push_subs WHERE endpoint = ?').bind(only).all()).results
    : (await env.DB.prepare('SELECT * FROM push_subs LIMIT ' + MAX_SUBS).all()).results;
  if (!subs.length) return 'nessun telefono registrato';
  const v = await vapid(env), data = await collect(env, subs), jwts = {}, gone = [];
  let sent = 0, status = 0;
  for (const s of subs) {
    const lines = buildLines(data.rows, nowLocal.slice(0, 10), data.urgent, data.soon, JSON.parse(s.depts));
    if (!lines.length && !only) continue;
    status = await sendOne(v, jwts, s, {
      title: only && !lines.length ? 'Scadenzario: prova' : 'Scadenzario',
      body: lines.length ? lines.join('\n') : 'Le notifiche funzionano. Nessun prodotto scaduto o in scadenza.',
      tag: 'scadenze', url: '/'
    });
    if (status === 404 || status === 410) gone.push(s.endpoint); else if (status >= 200 && status < 300) sent++;
  }
  if (gone.length) await env.DB.batch(gone.map(e => env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(e)));
  return only ? { status } : 'inviate ' + sent + ' su ' + subs.length;
}

/* ---------- richieste dall'app ---------- */
export async function handlePush(env, s, method, rest, body, HttpError, nowLocal) {
  const bad = (m) => new HttpError(400, m), name = rest.join('/');
  await schema(env);
  if (method === 'GET' && name === 'key') return { key: (await vapid(env)).pub };
  const endpoint = String((body && body.endpoint) || '');
  if (method === 'POST' && name === 'subscribe') {
    let u; try { u = new URL(endpoint); } catch (e) { throw bad('Indirizzo notifiche non valido.'); }
    if (u.protocol !== 'https:' || endpoint.length > 700 || !OK_HOST.test(u.hostname)) throw bad('Servizio di notifiche non supportato.');
    const k = (body && body.keys) || {};
    let pk, au; try { pk = unb64u(k.p256dh); au = unb64u(k.auth); } catch (e) { throw bad('Chiavi notifiche non valide.'); }
    if (pk.length !== 65 || pk[0] !== 4 || au.length !== 16) throw bad('Chiavi notifiche non valide.');
    let depts = [s.dept];
    if (s.admin) {
      const all = (await env.DB.prepare('SELECT name FROM depts').all()).results.map(r => r.name);
      depts = (Array.isArray(body.depts) ? body.depts : []).filter((d, i, a) => all.includes(d) && a.indexOf(d) === i);
      if (!depts.length) throw bad('Scegli almeno un reparto.');
    }
    const ex = await env.DB.prepare('SELECT 1 AS x FROM push_subs WHERE endpoint = ?').bind(endpoint).first();
    if (!ex) {
      const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subs').first();
      if (n.n >= MAX_SUBS) throw bad('Troppi telefoni registrati per le notifiche (massimo ' + MAX_SUBS + ').');
    }
    await env.DB.prepare('INSERT INTO push_subs (endpoint, p256dh, auth, depts, who, admin, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(endpoint) DO UPDATE SET p256dh = ?2, auth = ?3, depts = ?4, who = ?5, admin = ?6')
      .bind(endpoint, k.p256dh, k.auth, JSON.stringify(depts), s.op || '', s.admin ? 1 : 0, Date.now()).run();
    return { ok: true, depts };
  }
  if (method === 'POST' && name === 'unsubscribe') {
    await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(endpoint).run();
    return { ok: true };
  }
  if (method === 'POST' && name === 'status') {
    const r = await env.DB.prepare('SELECT depts FROM push_subs WHERE endpoint = ?').bind(endpoint).first();
    return { subscribed: !!r, depts: r ? JSON.parse(r.depts) : [] };
  }
  if (method === 'POST' && name === 'test') {
    const r = await env.DB.prepare('SELECT 1 AS x FROM push_subs WHERE endpoint = ?').bind(endpoint).first();
    if (!r) throw bad('Questo telefono non e\' registrato: attiva prima le notifiche.');
    return await runDaily(env, nowLocal, endpoint);
  }
  throw new HttpError(404, 'Funzione non trovata.');
}
