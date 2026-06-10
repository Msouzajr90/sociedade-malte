import { neon } from '@neondatabase/serverless';
import { scryptSync, randomBytes, timingSafeEqual, createHmac, randomUUID } from 'crypto';

const CONN =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.DATABASE_URL_UNPOOLED ||
  process.env.POSTGRES_URL_NON_POOLING;

const sql = CONN ? neon(CONN) : null;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.AUTH_SECRET || ADMIN_PASSWORD || 'malte-dev-secret-change-me';
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 30; // 30 dias

// ---------- Senhas (hash salgado) ----------
function hashPass(pw) {
  const salt = randomBytes(16).toString('hex');
  const h = scryptSync(String(pw), salt, 64).toString('hex');
  return salt + ':' + h;
}
function verifyPass(pw, stored) {
  if (!stored || stored.indexOf(':') < 0) return false;
  const [salt, h] = stored.split(':');
  const calc = scryptSync(String(pw), salt, 64);
  const orig = Buffer.from(h, 'hex');
  return calc.length === orig.length && timingSafeEqual(calc, orig);
}

// ---------- Tokens (HMAC assinado) ----------
function makeToken(payload) {
  const body = { ...payload, exp: Date.now() + TOKEN_TTL };
  const data = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = createHmac('sha256', SECRET).update(data).digest('base64url');
  return data + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expect = createHmac('sha256', SECRET).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]); const b = Buffer.from(expect);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch (e) { return null; }
}
function bearer(req) {
  const h = req.headers['authorization'] || req.headers['Authorization'] || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}

// ---------- Exemplos (semeados na 1ª vez) ----------
const SEED_PW = 'confraria'; // senha padrão dos membros de exemplo (trocar depois)
const SEED = {
  members: [
    { id: 'm1', name: 'Frodo' }, { id: 'm2', name: 'Sam' }, { id: 'm3', name: 'Gandalf' },
    { id: 'm4', name: 'Gimli' }, { id: 'm5', name: 'Legolas' },
  ],
  beers: [
    { id: 'b1', name: 'Stout do Condado', brewery: 'Dragão Verde', style: 'Imperial Stout' },
    { id: 'b2', name: 'IPA de Mordor', brewery: 'Barad-dûr', style: 'Double IPA' },
    { id: 'b3', name: 'Weiss de Lórien', brewery: 'Galadhrim', style: 'Witbier' },
    { id: 'b4', name: 'Hidromel de Valfenda', brewery: 'Casa de Elrond', style: 'Braggot' },
  ],
  tastings: [
    { beer: 'b1', m: 'm1', s: 9, n: 'Café e chocolate, encorpada. Digna de um segundo desjejum.' },
    { beer: 'b1', m: 'm2', s: 8.5, n: 'Cremosa, fácil de beber.' },
    { beer: 'b2', m: 'm4', s: 7.5, n: 'Amargor que arde como a Montanha da Perdição.' },
    { beer: 'b2', m: 'm3', s: 6, n: 'Forte demais para meu gosto.' },
    { beer: 'b3', m: 'm5', s: 9.5, n: 'Leve, cítrica, élfica. Perfeita.' },
    { beer: 'b3', m: 'm1', s: 8, n: 'Refrescante.' },
    { beer: 'b4', m: 'm3', s: 8.5, n: 'Mel e malte em concílio.' },
  ],
};

async function ensureSetup() {
  await sql`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`;
  const sv = await sql`SELECT v FROM meta WHERE k = 'schema_version'`;
  const version = sv.length ? Number(sv[0].v) : 0;

  if (version < 2) {
    // Atualização de estrutura: recria as tabelas (apaga dados de EXEMPLO da v1).
    await sql`DROP TABLE IF EXISTS tastings`;
    await sql`DROP TABLE IF EXISTS beers`;
    await sql`DROP TABLE IF EXISTS members`;
  }

  await sql`CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS beers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    brewery TEXT,
    style TEXT,
    image TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS tastings (
    id TEXT PRIMARY KEY,
    beer_id TEXT REFERENCES beers(id) ON DELETE CASCADE,
    member_id TEXT REFERENCES members(id) ON DELETE CASCADE,
    score REAL NOT NULL,
    notes TEXT,
    date DATE DEFAULT CURRENT_DATE
  )`;

  if (version < 2) {
    const ph = hashPass(SEED_PW);
    for (const m of SEED.members) {
      await sql`INSERT INTO members (id, name, pass_hash) VALUES (${m.id}, ${m.name}, ${ph})
                ON CONFLICT (id) DO NOTHING`;
    }
    for (const b of SEED.beers) {
      await sql`INSERT INTO beers (id, name, brewery, style) VALUES (${b.id}, ${b.name}, ${b.brewery}, ${b.style})
                ON CONFLICT (id) DO NOTHING`;
    }
    for (const t of SEED.tastings) {
      await sql`INSERT INTO tastings (id, beer_id, member_id, score, notes, date)
                VALUES (${randomUUID()}, ${t.beer}, ${t.m}, ${t.s}, ${t.n}, CURRENT_DATE)`;
    }
    await sql`INSERT INTO meta (k, v) VALUES ('schema_version', '2')
              ON CONFLICT (k) DO UPDATE SET v = '2'`;
  }
}

async function readState() {
  const members = await sql`SELECT id, name FROM members ORDER BY name ASC`;
  const beers = await sql`SELECT id, name, brewery, style, image FROM beers ORDER BY name ASC`;
  const rows = await sql`
    SELECT id, beer_id, member_id, score, notes, to_char(date,'YYYY-MM-DD') AS date
    FROM tastings ORDER BY date DESC, id DESC`;
  return {
    members,
    beers,
    tastings: rows.map((t) => ({
      id: t.id, beerId: t.beer_id, memberId: t.member_id,
      score: Number(t.score), notes: t.notes, date: t.date,
    })),
  };
}

async function getBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return await new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
const clean = (v) => (typeof v === 'string' ? v.trim() : v);

export default async function handler(req, res) {
  if (!sql) {
    return res.status(500).json({ error: 'Banco não conectado. Conecte um Postgres (Neon) ao projeto no Vercel.' });
  }
  try {
    await ensureSetup();
    const body = req.method === 'POST' ? await getBody(req) : {};
    const action = body.action;
    const payload = body.payload || {};

    // ---- Login (sem token) ----
    if (req.method === 'POST' && action === 'loginAdmin') {
      if (!ADMIN_PASSWORD) return res.status(500).json({ error: 'ADMIN_PASSWORD não configurada no Vercel.' });
      if (String(payload.password || '') !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Senha de administrador incorreta.' });
      return res.status(200).json({ token: makeToken({ sub: 'admin', role: 'admin', name: 'Administrador' }), me: { role: 'admin', name: 'Administrador' } });
    }
    if (req.method === 'POST' && action === 'loginMember') {
      const name = clean(payload.name);
      const rows = await sql`SELECT id, name, pass_hash FROM members WHERE lower(name) = lower(${name})`;
      if (rows.length === 0 || !verifyPass(payload.password, rows[0].pass_hash)) {
        return res.status(401).json({ error: 'Nome ou senha incorretos.' });
      }
      const m = rows[0];
      return res.status(200).json({ token: makeToken({ sub: m.id, role: 'member', name: m.name }), me: { id: m.id, role: 'member', name: m.name } });
    }

    // ---- Daqui em diante exige token ----
    const auth = verifyToken(bearer(req));
    if (!auth) return res.status(401).json({ error: 'Sessão expirada ou ausente. Entre novamente.' });
    const isAdmin = auth.role === 'admin';

    if (req.method === 'GET') {
      return res.status(200).json(await readState());
    }

    if (req.method === 'POST') {
      // --- Ações de administrador ---
      if (action === 'addMember') {
        if (!isAdmin) return res.status(403).json({ error: 'Apenas o administrador pode cadastrar confrades.' });
        const name = clean(payload.name);
        const pw = String(payload.password || '');
        if (!name) return res.status(400).json({ error: 'Informe o nome do confrade.' });
        if (pw.length < 4) return res.status(400).json({ error: 'A senha deve ter ao menos 4 caracteres.' });
        const exists = await sql`SELECT 1 FROM members WHERE lower(name) = lower(${name})`;
        if (exists.length) return res.status(400).json({ error: 'Já existe um confrade com esse nome.' });
        await sql`INSERT INTO members (id, name, pass_hash) VALUES (${randomUUID()}, ${name}, ${hashPass(pw)})`;

      } else if (action === 'setPassword') {
        if (!isAdmin) return res.status(403).json({ error: 'Apenas o administrador pode redefinir senhas.' });
        const pw = String(payload.password || '');
        if (pw.length < 4) return res.status(400).json({ error: 'A senha deve ter ao menos 4 caracteres.' });
        await sql`UPDATE members SET pass_hash = ${hashPass(pw)} WHERE id = ${String(payload.id || '')}`;

      } else if (action === 'deleteMember') {
        if (!isAdmin) return res.status(403).json({ error: 'Apenas o administrador pode remover confrades.' });
        await sql`DELETE FROM members WHERE id = ${String(payload.id || '')}`;

      // --- Catálogo de cervejas (qualquer logado adiciona; admin remove) ---
      } else if (action === 'addBeer') {
        const name = clean(payload.name);
        if (!name) return res.status(400).json({ error: 'Dê um nome à cerveja.' });
        let img = payload.image || null;
        if (img && (typeof img !== 'string' || img.length > 600000)) {
          return res.status(400).json({ error: 'Imagem muito grande. Use uma foto menor.' });
        }
        await sql`INSERT INTO beers (id, name, brewery, style, image)
          VALUES (${randomUUID()}, ${name}, ${clean(payload.brewery) || null}, ${clean(payload.style) || null}, ${img})`;

      } else if (action === 'deleteBeer') {
        if (!isAdmin) return res.status(403).json({ error: 'Apenas o administrador pode remover cervejas do catálogo.' });
        await sql`DELETE FROM beers WHERE id = ${String(payload.id || '')}`;

      // --- Degustações (membros) ---
      } else if (action === 'addTasting') {
        if (auth.role !== 'member') return res.status(403).json({ error: 'Entre como confrade para registrar degustações.' });
        const beerId = String(payload.beerId || '');
        const score = Number(payload.score);
        const beer = await sql`SELECT 1 FROM beers WHERE id = ${beerId}`;
        if (!beer.length) return res.status(400).json({ error: 'Escolha uma cerveja do catálogo.' });
        if (!(score >= 0 && score <= 10)) return res.status(400).json({ error: 'Nota inválida.' });
        await sql`INSERT INTO tastings (id, beer_id, member_id, score, notes, date)
          VALUES (${randomUUID()}, ${beerId}, ${auth.sub}, ${score}, ${clean(payload.notes) || null}, CURRENT_DATE)`;

      } else if (action === 'deleteTasting') {
        const id = String(payload.id || '');
        if (isAdmin) {
          await sql`DELETE FROM tastings WHERE id = ${id}`;
        } else {
          await sql`DELETE FROM tastings WHERE id = ${id} AND member_id = ${auth.sub}`;
        }

      } else {
        return res.status(400).json({ error: 'Ação desconhecida.' });
      }

      return res.status(200).json(await readState());
    }

    return res.status(405).json({ error: 'Método não permitido.' });
  } catch (e) {
    return res.status(500).json({ error: String((e && e.message) || e) });
  }
}
