// Scadenzario: server (Cloudflare Worker + database D1).
// Le pagine (cartella public/) sono servite direttamente da Cloudflare; a questo programma arrivano solo
// le richieste a /api/... (vedi run_worker_first in wrangler.jsonc). Il database e' il binding "DB";
// la password dell'amministratore e' il segreto "ADMIN_PASSWORD" (impostato su Cloudflare, mai nel codice).

const TZ = 'Europe/Rome';
const ADMIN_DEPT = 'Amministratore';
const ADMIN_NAME = 'Andrea Agamennone';
const HOURS_OP = 12;          // durata del login di un operatore (poi serve di nuovo il PIN)
const HOURS_ADMIN = 72;       // durata del login dell'amministratore
const TICKET_MIN = 10;        // tempo per scegliere nome e PIN dopo la password del reparto
const MAX_FAILS = 5;          // tentativi errati prima del blocco
const LOCK_MIN = 10;          // minuti di blocco
const ITER = 10000;           // giri dell'hash: volutamente leggero (limite di 10 ms di CPU del piano gratuito)
const MAX_PHOTO = 400000;     // caratteri massimi di una foto (circa 300 KB)
const CLOSED_IN_STATE = 100;  // aperture chiuse incluse nell'elenco principale

const enc = new TextEncoder();

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => new HttpError(400, m);

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
});

/* ---------- utilita' ---------- */
const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const rand = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return toHex(a); };
const sha256 = async (s) => toHex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
async function derive(value, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(value), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: ITER }, k, 256));
}
function same(a, b) {   // confronto a tempo costante
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
const akey = (n) => String(n || '').trim().toLowerCase().replace(/\s+/g, ' ');
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);
const isDT = (s) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s);

function nowLocal() {   // ora del negozio, nello stesso formato usato dall'app
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(new Date()).map(x => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
}

async function readBody(request) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > 700000) throw new HttpError(413, 'Richiesta troppo grande.');
  try { const b = await request.json(); return b && typeof b === 'object' ? b : {}; }
  catch (e) { throw bad('Richiesta non valida.'); }
}

/* ---------- blocco dopo tentativi errati ---------- */
async function checkLock(env, key) {
  const r = await env.DB.prepare('SELECT until FROM attempts WHERE k = ?').bind(key).first();
  const now = Date.now();
  if (r && r.until > now) throw new HttpError(429, 'Troppi tentativi errati. Riprova tra ' + Math.max(1, Math.ceil((r.until - now) / 60000)) + ' minuti.');
}
async function registerFail(env, key, message) {
  const now = Date.now();
  const r = await env.DB.prepare('SELECT fails, last FROM attempts WHERE k = ?').bind(key).first();
  let fails = (r && now - r.last < 3600000 ? r.fails : 0) + 1;
  let until = 0;
  if (fails >= MAX_FAILS) { until = now + LOCK_MIN * 60000; fails = 0; }
  await env.DB.prepare('INSERT INTO attempts (k, fails, until, last) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(k) DO UPDATE SET fails = ?2, until = ?3, last = ?4')
    .bind(key, fails, until, now).run();
  if (until) throw new HttpError(429, 'Troppi tentativi errati. Accesso bloccato per ' + LOCK_MIN + ' minuti.');
  throw new HttpError(401, message);
}
const clearFails = (env, key) => env.DB.prepare('DELETE FROM attempts WHERE k = ?').bind(key).run();

/* ---------- sessioni ---------- */
async function newToken(env, kind, data, minutes) {
  const token = rand(32);
  await env.DB.prepare('INSERT INTO sessions (token_hash, kind, dept, op_id, op_name, admin, expires) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(await sha256(token), kind, data.dept || null, data.opId || null, data.op || null, data.admin ? 1 : 0, Date.now() + minutes * 60000).run();
  return token;
}
async function lookup(env, token, kind) {
  if (!/^[0-9a-f]{64}$/.test(String(token || ''))) return null;
  const hash = await sha256(token);
  const r = await env.DB.prepare('SELECT kind, dept, op_id, op_name, admin, expires FROM sessions WHERE token_hash = ?').bind(hash).first();
  if (!r || r.kind !== kind || r.expires < Date.now()) return null;
  return { hash, dept: r.dept, opId: r.op_id, op: r.op_name, admin: !!r.admin };
}
async function requireSession(env, request) {
  const m = /^Bearer (\S+)$/.exec(request.headers.get('Authorization') || '');
  const s = m && await lookup(env, m[1], 'session');
  if (!s) throw new HttpError(401, 'Sessione scaduta: accedi di nuovo.');
  return s;
}
const requireAdmin = (s) => { if (!s.admin) throw new HttpError(403, 'Operazione riservata all\'amministratore.'); };
const sweep = (env) => env.DB.prepare('DELETE FROM sessions WHERE expires < ?').bind(Date.now()).run();
const bumpRev = (env) => env.DB.prepare("UPDATE settings SET v = CAST(v AS INTEGER) + 1 WHERE k = 'rev'");

/* ---------- conversioni riga -> oggetto dell'app ---------- */
const openingOut = (r) => ({
  id: r.id, dept: r.dept, articolo: r.articolo, lotto: r.lotto, scad: r.scad, aperto: r.aperto,
  durata: r.durata == null ? '' : r.durata, stato: r.stato, opAperto: r.op_aperto,
  chiusoIl: r.chiuso_il, motivo: r.motivo, opChiuso: r.op_chiuso, hasFoto: !!r.has_foto
});
const arrivalOut = (r) => ({ id: r.id, dept: r.dept, articolo: r.articolo, lotto: r.lotto, scad: r.scad, arrivatoIl: r.arrivato_il, opArrivo: r.op_arrivo, stato: r.stato });
const OPENING_COLS = 'id, dept, articolo, lotto, scad, aperto, durata, stato, op_aperto, chiuso_il, motivo, op_chiuso, has_foto';

/* ---------- login ---------- */
async function loginDept(env, b) {
  const dept = clean(b.dept, 60), password = String(b.password ?? '');
  const d = await env.DB.prepare('SELECT name, pw_salt, pw_hash FROM depts WHERE name = ?').bind(dept).first();
  if (!d) throw new HttpError(404, 'Reparto non trovato.');
  if (!d.pw_hash) throw new HttpError(403, 'La password di questo reparto non e\' ancora stata impostata: chiedi all\'amministratore.');
  const key = 'd:' + dept;
  await checkLock(env, key);
  if (!same(await derive(password, d.pw_salt), d.pw_hash)) await registerFail(env, key, 'Password del reparto errata.');
  await clearFails(env, key);
  await sweep(env);
  const ticket = await newToken(env, 'ticket', { dept }, TICKET_MIN);
  const ops = await env.DB.prepare('SELECT id, name, pin_hash IS NOT NULL AS hasPin FROM operators WHERE dept = ? ORDER BY name COLLATE NOCASE').bind(dept).all();
  return { ticket, operators: ops.results.map(o => ({ id: o.id, name: o.name, hasPin: !!o.hasPin })) };
}

async function loginOperator(env, b) {
  const t = await lookup(env, b.ticket, 'ticket');
  if (!t) throw new HttpError(401, 'Tempo scaduto: inserisci di nuovo la password del reparto.');
  const pin = String(b.pin ?? ''), pin2 = String(b.pin2 ?? '');
  if (!/^\d{4,6}$/.test(pin)) throw bad('Il PIN deve essere di 4-6 cifre.');
  let op;
  const newName = clean(b.newName, 40);
  if (b.opId === '__new__' || (!b.opId && newName)) {
    if (!newName) throw bad('Scrivi il tuo nome.');
    if (pin !== pin2) throw bad('I due PIN non coincidono.');
    const dup = await env.DB.prepare('SELECT id FROM operators WHERE dept = ? AND lower(name) = lower(?)').bind(t.dept, newName).first();
    if (dup) throw new HttpError(409, 'Esiste gia\' un operatore con questo nome: sceglilo dall\'elenco.');
    const salt = rand(16);
    op = { id: 'p' + rand(5), name: newName };
    await env.DB.prepare('INSERT INTO operators (id, dept, name, pin_salt, pin_hash) VALUES (?, ?, ?, ?, ?)')
      .bind(op.id, t.dept, op.name, salt, await derive(pin, salt)).run();
    await bumpRev(env).run();
  } else {
    const r = await env.DB.prepare('SELECT id, name, pin_salt, pin_hash FROM operators WHERE id = ? AND dept = ?').bind(clean(b.opId, 40), t.dept).first();
    if (!r) throw new HttpError(404, 'Operatore non trovato.');
    const key = 'o:' + r.id;
    await checkLock(env, key);
    if (!r.pin_hash) {   // primo accesso: l'operatore sceglie il PIN
      if (pin !== pin2) throw bad('I due PIN non coincidono.');
      const salt = rand(16);
      const res = await env.DB.prepare('UPDATE operators SET pin_salt = ?, pin_hash = ? WHERE id = ? AND pin_hash IS NULL')
        .bind(salt, await derive(pin, salt), r.id).run();
      if (!res.meta || res.meta.changes !== 1) throw new HttpError(409, 'Il PIN e\' appena stato scelto da qualcun altro: riprova.');
      await bumpRev(env).run();
    } else if (!same(await derive(pin, r.pin_salt), r.pin_hash)) {
      await registerFail(env, key, 'PIN errato.');
    } else {
      await clearFails(env, key);
    }
    op = { id: r.id, name: r.name };
  }
  const token = await newToken(env, 'session', { dept: t.dept, opId: op.id, op: op.name, admin: false }, HOURS_OP * 60);
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(t.hash).run();
  return { token, dept: t.dept, op: op.name, admin: false };
}

async function loginAdmin(env, b) {
  if (!env.ADMIN_PASSWORD) throw new HttpError(503, 'La password dell\'amministratore non e\' ancora stata impostata su Cloudflare (variabile ADMIN_PASSWORD).');
  await checkLock(env, 'admin');
  const ok = same(await sha256(String(b.password ?? '')), await sha256(String(env.ADMIN_PASSWORD)));
  if (!ok) await registerFail(env, 'admin', 'Password errata.');
  await clearFails(env, 'admin');
  await sweep(env);
  const token = await newToken(env, 'session', { dept: ADMIN_DEPT, op: ADMIN_NAME, admin: true }, HOURS_ADMIN * 60);
  return { token, dept: ADMIN_DEPT, op: ADMIN_NAME, admin: true };
}

/* ---------- dati ---------- */
async function getState(env, s) {
  const q = (sql, ...p) => env.DB.prepare(sql).bind(...p);
  const [st, dp, du, op, cl, ar, ops] = await env.DB.batch([
    q('SELECT k, v FROM settings'),
    q('SELECT name, pw_hash IS NOT NULL AS hasPw FROM depts ORDER BY pos, name'),
    q('SELECT k, days, pending FROM durations'),
    q(`SELECT ${OPENING_COLS} FROM openings WHERE stato = 'aperto'`),
    q(`SELECT ${OPENING_COLS} FROM openings WHERE stato = 'chiuso' ORDER BY chiuso_il DESC LIMIT ${CLOSED_IN_STATE}`),
    q("SELECT id, dept, articolo, lotto, scad, arrivato_il, op_arrivo, stato FROM arrivals WHERE stato = 'giacenza' OR id IN (SELECT id FROM arrivals ORDER BY arrivato_il DESC LIMIT 100)"),
    q(s.admin ? 'SELECT id, dept, name, pin_hash IS NOT NULL AS hasPin FROM operators ORDER BY name COLLATE NOCASE' : 'SELECT 1 WHERE 0')
  ]);
  const set = Object.fromEntries(st.results.map(r => [r.k, r.v]));
  const out = {
    rev: Number(set.rev), shop: JSON.parse(set.shop || '{}'), urgentDays: Number(set.urgentDays), soonDays: Number(set.soonDays),
    depts: dp.results.map(d => d.name),
    durations: Object.fromEntries(du.results.map(r => [r.k, r.days])),
    durPending: Object.fromEntries(du.results.filter(r => r.pending).map(r => [r.k, true])),
    openings: op.results.concat(cl.results).map(openingOut),
    arrivals: ar.results.map(arrivalOut)
  };
  if (s.admin) {
    out.deptHasPw = Object.fromEntries(dp.results.map(d => [d.name, !!d.hasPw]));
    out.staff = {};
    dp.results.forEach(d => { out.staff[d.name] = []; });
    ops.results.forEach(o => { (out.staff[o.dept] = out.staff[o.dept] || []).push({ id: o.id, name: o.name, hasPin: !!o.hasPin }); });
  }
  return out;
}

async function listOpenings(env, url, all) {
  const from = url.searchParams.get('from') || '', to = url.searchParams.get('to') || '';
  if ((from && !isDay(from)) || (to && !isDay(to))) throw bad('Date non valide.');
  const r = await env.DB.prepare(
    `SELECT ${OPENING_COLS} FROM openings
     WHERE (?1 = '' OR aperto IS NULL OR aperto = '' OR aperto <= ?1 || 'T23:59')
       AND (?2 = '' OR stato <> 'chiuso' OR chiuso_il IS NULL OR chiuso_il >= ?2 || 'T00:00')
     ORDER BY aperto DESC LIMIT ${all ? 20000 : 5000}`).bind(to, from).all();
  return { openings: r.results.map(openingOut) };
}

async function saveOpening(env, s, b) {
  const dept = s.admin ? clean(b.dept, 60) : s.dept;
  const d = await env.DB.prepare('SELECT name FROM depts WHERE name = ?').bind(dept).first();
  if (!d) throw bad('Reparto non valido.');
  const articolo = clean(b.articolo, 120), lotto = clean(b.lotto, 60);
  const scad = clean(b.scad, 10), aperto = clean(b.aperto, 16);
  if (scad && !isDay(scad)) throw bad('Scadenza non valida.');
  if (aperto && !isDT(aperto)) throw bad('Data di apertura non valida.');
  let durata = null;
  if (b.durata !== '' && b.durata != null) {
    durata = Number(b.durata);
    if (!Number.isInteger(durata) || durata < 0 || durata > 3650) throw bad('Durata non valida.');
  }
  if (!articolo && !lotto && !scad) throw bad('Inserisci almeno articolo, lotto o scadenza.');
  const k = akey(articolo), now = nowLocal();
  let id = clean(b.id, 40), existing = null;
  if (id) {
    existing = await env.DB.prepare('SELECT id, dept, stato, op_aperto FROM openings WHERE id = ?').bind(id).first();
    if (!existing) throw new HttpError(404, 'Apertura non trovata.');
    if (existing.stato !== 'aperto') throw new HttpError(409, 'Questa apertura e\' gia\' stata chiusa.');
    if (!s.admin && existing.dept !== s.dept) throw new HttpError(403, 'Non puoi modificare un\'apertura di un altro reparto.');
  } else id = 'o' + rand(6);

  const stmts = [];
  const P = (sql, ...p) => env.DB.prepare(sql).bind(...p);
  if (k && durata > 0) {   // la durata si impara dal primo inserimento; dopo, solo l'amministratore la cambia
    const cur = await env.DB.prepare('SELECT days FROM durations WHERE k = ?').bind(k).first();
    if (s.admin) stmts.push(P('INSERT INTO durations (k, days, pending) VALUES (?1, ?2, 0) ON CONFLICT(k) DO UPDATE SET days = ?2, pending = 0', k, durata));
    else if (!cur) stmts.push(P('INSERT INTO durations (k, days, pending) VALUES (?, ?, 1)', k, durata));
  }
  if (k) {   // stesso articolo gia' aperto nello stesso reparto: il vecchio si chiude
    const dups = await env.DB.prepare("SELECT id, articolo FROM openings WHERE stato = 'aperto' AND dept = ? AND id <> ?").bind(dept, id).all();
    dups.results.filter(r => akey(r.articolo) === k).forEach(r => {
      stmts.push(P("UPDATE openings SET stato = 'chiuso', chiuso_il = ?, motivo = 'Sostituito da nuova apertura', op_chiuso = ?, has_foto = 0, updated_at = ? WHERE id = ? AND stato = 'aperto'", now, s.op, now, r.id));
      stmts.push(P('DELETE FROM photos WHERE opening_id = ?', r.id));
    });
  }
  if (existing) stmts.push(P('UPDATE openings SET dept = ?, articolo = ?, lotto = ?, scad = ?, aperto = ?, durata = ?, updated_at = ? WHERE id = ?', dept, articolo, lotto, scad, aperto, durata, now, id));
  else stmts.push(P("INSERT INTO openings (id, dept, articolo, lotto, scad, aperto, durata, stato, op_aperto, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'aperto', ?, ?, ?)", id, dept, articolo, lotto, scad, aperto, durata, s.op, now, now));
  if (typeof b.foto === 'string' && b.foto) {
    if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(b.foto) || b.foto.length > MAX_PHOTO) throw bad('Foto non valida o troppo grande.');
    stmts.push(P('INSERT INTO photos (opening_id, data) VALUES (?1, ?2) ON CONFLICT(opening_id) DO UPDATE SET data = ?2', id, b.foto));
    stmts.push(P('UPDATE openings SET has_foto = 1 WHERE id = ?', id));
  }
  const fa = clean(b.fromArrival, 40);
  if (fa) stmts.push(s.admin ? P("UPDATE arrivals SET stato = 'aperto' WHERE id = ? AND stato = 'giacenza'", fa) : P("UPDATE arrivals SET stato = 'aperto' WHERE id = ? AND stato = 'giacenza' AND dept = ?", fa, s.dept));
  stmts.push(bumpRev(env));
  await env.DB.batch(stmts);
  return { id };
}

async function closeOpening(env, s, id) {
  const r = await env.DB.prepare('SELECT dept, stato FROM openings WHERE id = ?').bind(id).first();
  if (!r) throw new HttpError(404, 'Apertura non trovata.');
  if (!s.admin && r.dept !== s.dept) throw new HttpError(403, 'Non puoi chiudere un\'apertura di un altro reparto.');
  if (r.stato === 'chiuso') return { ok: true };
  const now = nowLocal();
  await env.DB.batch([
    env.DB.prepare("UPDATE openings SET stato = 'chiuso', chiuso_il = ?, motivo = 'Terminato al banco', op_chiuso = ?, has_foto = 0, updated_at = ? WHERE id = ? AND stato = 'aperto'").bind(now, s.op, now, id),
    env.DB.prepare('DELETE FROM photos WHERE opening_id = ?').bind(id),
    bumpRev(env)
  ]);
  return { ok: true };
}

async function saveArrival(env, s, b) {
  const dept = s.admin ? clean(b.dept, 60) : s.dept;
  const d = await env.DB.prepare('SELECT name FROM depts WHERE name = ?').bind(dept).first();
  if (!d) throw bad('Reparto non valido.');
  const articolo = clean(b.articolo, 120), lotto = clean(b.lotto, 60), scad = clean(b.scad, 10);
  if (scad && !isDay(scad)) throw bad('Scadenza non valida.');
  if (!articolo && !lotto && !scad) throw bad('Inserisci almeno articolo, lotto o scadenza.');
  let id = clean(b.id, 40);
  if (id) {
    const r = await env.DB.prepare('SELECT dept FROM arrivals WHERE id = ?').bind(id).first();
    if (!r) throw new HttpError(404, 'Arrivo non trovato.');
    if (!s.admin && r.dept !== s.dept) throw new HttpError(403, 'Non puoi modificare un arrivo di un altro reparto.');
    await env.DB.batch([
      env.DB.prepare('UPDATE arrivals SET dept = ?, articolo = ?, lotto = ?, scad = ? WHERE id = ?').bind(dept, articolo, lotto, scad, id),
      bumpRev(env)
    ]);
  } else {
    id = 'a' + rand(6);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO arrivals (id, dept, articolo, lotto, scad, arrivato_il, op_arrivo, stato) VALUES (?, ?, ?, ?, ?, ?, ?, 'giacenza')").bind(id, dept, articolo, lotto, scad, nowLocal(), s.op),
      bumpRev(env)
    ]);
  }
  return { id };
}

async function removeArrival(env, s, id) {
  const r = await env.DB.prepare('SELECT dept FROM arrivals WHERE id = ?').bind(id).first();
  if (!r) throw new HttpError(404, 'Arrivo non trovato.');
  if (!s.admin && r.dept !== s.dept) throw new HttpError(403, 'Non puoi rimuovere un arrivo di un altro reparto.');
  await env.DB.batch([env.DB.prepare("UPDATE arrivals SET stato = 'rimosso' WHERE id = ? AND stato = 'giacenza'").bind(id), bumpRev(env)]);
  return { ok: true };
}

/* ---------- amministrazione ---------- */
async function admin(env, s, request, path) {
  requireAdmin(s);
  const P = (sql, ...p) => env.DB.prepare(sql).bind(...p);
  const run = async (...stmts) => { await env.DB.batch(stmts.concat([bumpRev(env)])); return { ok: true }; };
  const m = request.method, name = path.join('/');

  if (m === 'GET' && name === 'export') {
    const t = async (sql) => (await env.DB.prepare(sql).all()).results;
    return {
      esportatoIl: nowLocal(),
      impostazioni: await t('SELECT k, v FROM settings WHERE k <> \'rev\''),
      reparti: await t('SELECT name FROM depts ORDER BY pos'),
      operatori: await t('SELECT id, dept, name FROM operators'),
      durate: await t('SELECT k, days, pending FROM durations'),
      aperture: (await t(`SELECT ${OPENING_COLS}, created_at, updated_at FROM openings ORDER BY aperto`)),
      arrivi: await t('SELECT * FROM arrivals')
    };
  }
  if (m !== 'POST') throw new HttpError(405, 'Metodo non consentito.');
  const b = await readBody(request);

  if (name === 'settings') {
    const u = Number(b.urgentDays), so = Number(b.soonDays);
    if (!Number.isInteger(u) || !Number.isInteger(so) || u < 0 || so < 0 || u > 365 || so > 365) throw bad('Giorni non validi.');
    const sh = b.shop || {};
    const shop = JSON.stringify({ name: clean(sh.name, 120), address: clean(sh.address, 160), piva: clean(sh.piva, 30) });
    return run(
      P("INSERT INTO settings (k, v) VALUES ('urgentDays', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", String(u)),
      P("INSERT INTO settings (k, v) VALUES ('soonDays', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", String(so)),
      P("INSERT INTO settings (k, v) VALUES ('shop', ?1) ON CONFLICT(k) DO UPDATE SET v = ?1", shop));
  }
  if (name === 'durations') {
    const k = akey(clean(b.k, 120)), days = Number(b.days);
    if (!k || !Number.isInteger(days) || days < 1 || days > 3650) throw bad('Inserisci articolo e giorni.');
    return run(P('INSERT INTO durations (k, days, pending) VALUES (?1, ?2, 0) ON CONFLICT(k) DO UPDATE SET days = ?2, pending = 0', k, days));
  }
  if (name === 'durations/validate') return run(P('UPDATE durations SET pending = 0 WHERE k = ?', akey(clean(b.k, 120))));
  if (name === 'durations/delete') return run(P('DELETE FROM durations WHERE k = ?', akey(clean(b.k, 120))));

  if (name === 'dept') {
    const n = clean(b.name, 40), pw = String(b.password ?? '');
    if (!n || n === ADMIN_DEPT) throw bad('Nome reparto non valido.');
    if (pw.length < 6 || pw.length > 64) throw bad('La password del reparto deve avere almeno 6 caratteri.');
    if (await env.DB.prepare('SELECT 1 FROM depts WHERE lower(name) = lower(?)').bind(n).first()) throw new HttpError(409, 'Esiste gia\' un reparto con questo nome.');
    const salt = rand(16);
    return run(P('INSERT INTO depts (name, pos, pw_salt, pw_hash) VALUES (?, (SELECT COALESCE(MAX(pos), 0) + 1 FROM depts), ?, ?)', n, salt, await derive(pw, salt)));
  }
  if (name === 'dept/password') {
    const n = clean(b.name, 40), pw = String(b.password ?? '');
    if (pw.length < 6 || pw.length > 64) throw bad('La password del reparto deve avere almeno 6 caratteri.');
    if (!await env.DB.prepare('SELECT 1 FROM depts WHERE name = ?').bind(n).first()) throw new HttpError(404, 'Reparto non trovato.');
    const salt = rand(16);
    return run(P('UPDATE depts SET pw_salt = ?, pw_hash = ? WHERE name = ?', salt, await derive(pw, salt), n));
  }
  if (name === 'operator') {
    const n = clean(b.name, 40), dept = clean(b.dept, 40);
    if (!n) throw bad('Scrivi il nome dell\'operatore.');
    if (!await env.DB.prepare('SELECT 1 FROM depts WHERE name = ?').bind(dept).first()) throw new HttpError(404, 'Reparto non trovato.');
    if (await env.DB.prepare('SELECT 1 FROM operators WHERE dept = ? AND lower(name) = lower(?)').bind(dept, n).first()) throw new HttpError(409, 'Esiste gia\' un operatore con questo nome.');
    return run(P('INSERT INTO operators (id, dept, name) VALUES (?, ?, ?)', 'p' + rand(5), dept, n));
  }
  if (name === 'operator/delete') {
    const id = clean(b.id, 40);
    return run(P('DELETE FROM operators WHERE id = ?', id), P('DELETE FROM sessions WHERE op_id = ?', id));
  }
  if (name === 'operator/reset-pin') {
    const id = clean(b.id, 40);
    return run(P('UPDATE operators SET pin_salt = NULL, pin_hash = NULL WHERE id = ?', id), P('DELETE FROM sessions WHERE op_id = ?', id), P('DELETE FROM attempts WHERE k = ?', 'o:' + id));
  }
  throw new HttpError(404, 'Funzione non trovata.');
}

/* ---------- instradamento ---------- */
async function handle(request, env) {
  try {
    const url = new URL(request.url);
    if (!/^\/api(\/|$)/.test(url.pathname)) throw new HttpError(404, 'Non trovato.');
    if (!env.DB) throw new HttpError(500, 'Database non collegato: controlla il collegamento D1 (binding DB) in wrangler.jsonc.');
    const path = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
    const route = path.join('/'), m = request.method;

    if (m === 'GET' && route === 'depts') {
      const r = await env.DB.prepare('SELECT name FROM depts ORDER BY pos, name').all();
      return json({ depts: r.results.map(x => x.name) });
    }
    if (m === 'POST' && route === 'login/dept') return json(await loginDept(env, await readBody(request)));
    if (m === 'POST' && route === 'login/operator') return json(await loginOperator(env, await readBody(request)));
    if (m === 'POST' && route === 'login/admin') return json(await loginAdmin(env, await readBody(request)));

    const s = await requireSession(env, request);
    if (m === 'POST' && route === 'logout') {
      await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(s.hash).run();
      return json({ ok: true });
    }
    if (m === 'GET' && route === 'rev') {
      const r = await env.DB.prepare("SELECT v FROM settings WHERE k = 'rev'").first();
      return json({ rev: Number(r.v) });
    }
    if (m === 'GET' && route === 'state') return json(await getState(env, s));
    if (m === 'GET' && route === 'openings') return json(await listOpenings(env, url, url.searchParams.get('all') === '1'));
    if (m === 'GET' && path[0] === 'photos' && path.length === 2) {
      const r = await env.DB.prepare('SELECT data FROM photos WHERE opening_id = ?').bind(path[1]).first();
      return json({ data: r ? r.data : null });
    }
    if (m === 'POST' && route === 'openings') return json(await saveOpening(env, s, await readBody(request)));
    if (m === 'POST' && path[0] === 'openings' && path[2] === 'close' && path.length === 3) return json(await closeOpening(env, s, path[1]));
    if (m === 'POST' && route === 'arrivals') return json(await saveArrival(env, s, await readBody(request)));
    if (m === 'POST' && path[0] === 'arrivals' && path[2] === 'remove' && path.length === 3) return json(await removeArrival(env, s, path[1]));
    if (path[0] === 'admin') return json(await admin(env, s, request, path.slice(1)));
    throw new HttpError(404, 'Funzione non trovata.');
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e && e.stack || e);
    return json({ error: 'Errore del server. Riprova tra poco.' }, 500);
  }
}

export default { fetch: (request, env) => handle(request, env) };
