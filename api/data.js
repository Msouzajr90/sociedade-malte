import { neon } from '@neondatabase/serverless';
import { randomUUID } from 'crypto';

// O Neon (via integração do Vercel) injeta a connection string automaticamente.
// Tentamos os nomes de variável mais comuns, nesta ordem.
const CONN =
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_PRISMA_URL ||
  process.env.DATABASE_URL_UNPOOLED ||
  process.env.POSTGRES_URL_NON_POOLING;

const sql = neon(CONN);

// --- Exemplos fictícios, semeados uma única vez (podem ser apagados pelo app) ---
const SEED_MEMBERS = [
  { id: 'm1', name: 'Frodo' },
  { id: 'm2', name: 'Sam' },
  { id: 'm3', name: 'Gandalf' },
  { id: 'm4', name: 'Gimli' },
  { id: 'm5', name: 'Legolas' },
];
const SEED_TASTINGS = [
  { id: 't1', beer: 'Stout do Condado', brewery: 'Dragão Verde', style: 'Imperial Stout', memberId: 'm1', score: 9, notes: 'Café e chocolate, encorpada. Digna de um segundo desjejum.', date: '2025-02-14' },
  { id: 't2', beer: 'Stout do Condado', brewery: 'Dragão Verde', style: 'Imperial Stout', memberId: 'm2', score: 8.5, notes: 'Cremosa, fácil de beber.', date: '2025-02-14' },
  { id: 't3', beer: 'IPA de Mordor', brewery: 'Barad-dûr', style: 'Double IPA', memberId: 'm4', score: 7.5, notes: 'Amargor que arde como a Montanha da Perdição.', date: '2025-02-14' },
  { id: 't4', beer: 'IPA de Mordor', brewery: 'Barad-dûr', style: 'Double IPA', memberId: 'm3', score: 6, notes: 'Forte demais para meu gosto.', date: '2025-02-14' },
  { id: 't5', beer: 'Weiss de Lórien', brewery: 'Galadhrim', style: 'Witbier', memberId: 'm5', score: 9.5, notes: 'Leve, cítrica, élfica. Perfeita.', date: '2025-03-14' },
  { id: 't6', beer: 'Weiss de Lórien', brewery: 'Galadhrim', style: 'Witbier', memberId: 'm1', score: 8, notes: 'Refrescante.', date: '2025-03-14' },
  { id: 't7', beer: 'Hidromel de Valfenda', brewery: 'Casa de Elrond', style: 'Braggot', memberId: 'm3', score: 8.5, notes: 'Mel e malte em concílio.', date: '2025-03-14' },
];

async function ensureSetup() {
  await sql`CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS tastings (
    id TEXT PRIMARY KEY,
    beer TEXT NOT NULL,
    brewery TEXT,
    style TEXT,
    member_id TEXT,
    score REAL NOT NULL,
    notes TEXT,
    date DATE DEFAULT CURRENT_DATE
  )`;
  await sql`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`;

  const seeded = await sql`SELECT v FROM meta WHERE k = 'seeded'`;
  if (seeded.length === 0) {
    for (const m of SEED_MEMBERS) {
      await sql`INSERT INTO members (id, name) VALUES (${m.id}, ${m.name})
                ON CONFLICT (id) DO NOTHING`;
    }
    for (const t of SEED_TASTINGS) {
      await sql`INSERT INTO tastings (id, beer, brewery, style, member_id, score, notes, date)
                VALUES (${t.id}, ${t.beer}, ${t.brewery}, ${t.style}, ${t.memberId}, ${t.score}, ${t.notes}, ${t.date})
                ON CONFLICT (id) DO NOTHING`;
    }
    await sql`INSERT INTO meta (k, v) VALUES ('seeded', 'true') ON CONFLICT (k) DO NOTHING`;
  }
}

async function readState() {
  const members = await sql`SELECT id, name FROM members ORDER BY name ASC`;
  const rows = await sql`
    SELECT id, beer, brewery, style, member_id, score, notes,
           to_char(date, 'YYYY-MM-DD') AS date
    FROM tastings
    ORDER BY date DESC, id DESC`;
  return {
    members,
    tastings: rows.map((t) => ({
      id: t.id, beer: t.beer, brewery: t.brewery, style: t.style,
      memberId: t.member_id, score: Number(t.score), notes: t.notes, date: t.date,
    })),
  };
}

async function getBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return await new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function clean(v) { return (typeof v === 'string') ? v.trim() : v; }

export default async function handler(req, res) {
  if (!CONN) {
    return res.status(500).json({
      error: 'Banco de dados não conectado. Conecte um Postgres (Neon) ao projeto no painel do Vercel.',
    });
  }
  try {
    await ensureSetup();

    if (req.method === 'GET') {
      return res.status(200).json(await readState());
    }

    if (req.method === 'POST') {
      const { action, payload = {} } = await getBody(req);

      if (action === 'addMember') {
        const name = clean(payload.name);
        if (!name) return res.status(400).json({ error: 'Informe o nome do confrade.' });
        await sql`INSERT INTO members (id, name) VALUES (${randomUUID()}, ${name})`;

      } else if (action === 'deleteMember') {
        const id = String(payload.id || '');
        await sql`DELETE FROM tastings WHERE member_id = ${id}`;
        await sql`DELETE FROM members WHERE id = ${id}`;

      } else if (action === 'addTasting') {
        const beer = clean(payload.beer);
        const memberId = String(payload.memberId || '');
        const score = Number(payload.score);
        if (!beer) return res.status(400).json({ error: 'Dê um nome ao rótulo.' });
        if (!memberId) return res.status(400).json({ error: 'Escolha um confrade.' });
        if (!(score >= 0 && score <= 10)) return res.status(400).json({ error: 'Nota inválida.' });
        await sql`INSERT INTO tastings (id, beer, brewery, style, member_id, score, notes, date)
          VALUES (${randomUUID()}, ${beer}, ${clean(payload.brewery) || null}, ${clean(payload.style) || null},
                  ${memberId}, ${score}, ${clean(payload.notes) || null}, CURRENT_DATE)`;

      } else if (action === 'deleteTasting') {
        await sql`DELETE FROM tastings WHERE id = ${String(payload.id || '')}`;

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
