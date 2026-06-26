import { neon } from '@neondatabase/serverless';
import { scryptSync, randomBytes, timingSafeEqual, createHmac, randomUUID } from 'crypto';

const CONN =
  process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL ||
  process.env.DATABASE_URL_UNPOOLED || process.env.POSTGRES_URL_NON_POOLING;
const sql = CONN ? neon(CONN) : null;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SECRET = process.env.AUTH_SECRET || ADMIN_PASSWORD || 'malte-dev-secret-change-me';
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 30;

function hashPass(pw){ const salt=randomBytes(16).toString('hex'); const h=scryptSync(String(pw),salt,64).toString('hex'); return salt+':'+h; }
function verifyPass(pw,stored){ if(!stored||stored.indexOf(':')<0) return false; const [s,h]=stored.split(':');
  const c=scryptSync(String(pw),s,64), o=Buffer.from(h,'hex'); return c.length===o.length && timingSafeEqual(c,o); }
function makeToken(p){ const body={...p,exp:Date.now()+TOKEN_TTL}; const d=Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig=createHmac('sha256',SECRET).update(d).digest('base64url'); return d+'.'+sig; }
function verifyToken(t){ if(!t) return null; const p=t.split('.'); if(p.length!==2) return null;
  const e=createHmac('sha256',SECRET).update(p[0]).digest('base64url'); const a=Buffer.from(p[1]),b=Buffer.from(e);
  if(a.length!==b.length||!timingSafeEqual(a,b)) return null;
  try{ const o=JSON.parse(Buffer.from(p[0],'base64url').toString()); if(o.exp&&Date.now()>o.exp) return null; return o; }catch(_){ return null; } }
function bearer(req){ const h=req.headers['authorization']||req.headers['Authorization']||''; return h.startsWith('Bearer ')?h.slice(7):''; }

const SEED_PW='confraria';
const SEED={
  members:[{id:'m1',name:'Frodo'},{id:'m2',name:'Sam'},{id:'m3',name:'Gandalf'},{id:'m4',name:'Gimli'},{id:'m5',name:'Legolas'}],
  beers:[{id:'b1',name:'Stout do Condado',brewery:'Dragão Verde',style:'Imperial Stout'},
    {id:'b2',name:'IPA de Mordor',brewery:'Barad-dûr',style:'Double IPA'},
    {id:'b3',name:'Weiss de Lórien',brewery:'Galadhrim',style:'Witbier'},
    {id:'b4',name:'Hidromel de Valfenda',brewery:'Casa de Elrond',style:'Braggot'}],
  tastings:[{beer:'b1',m:'m1',s:9,n:'Café e chocolate, encorpada.'},{beer:'b1',m:'m2',s:8.5,n:'Cremosa, fácil de beber.'},
    {beer:'b2',m:'m4',s:7.5,n:'Amargor que arde como a Montanha da Perdição.'},{beer:'b2',m:'m3',s:6,n:'Forte demais para meu gosto.'},
    {beer:'b3',m:'m5',s:9.5,n:'Leve, cítrica, élfica. Perfeita.'},{beer:'b3',m:'m1',s:8,n:'Refrescante.'},
    {beer:'b4',m:'m3',s:8.5,n:'Mel e malte em concílio.'}],
};

async function ensureSetup(){
  await sql`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`;
  const sv=await sql`SELECT v FROM meta WHERE k='schema_version'`;
  const version=sv.length?Number(sv[0].v):0;
  const needV2=version<2, needV3=version<3, needV4=version<4;

  if(needV2){ await sql`DROP TABLE IF EXISTS tastings`; await sql`DROP TABLE IF EXISTS beers`; await sql`DROP TABLE IF EXISTS members`; }

  await sql`CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, pass_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS beers (id TEXT PRIMARY KEY, name TEXT NOT NULL, brewery TEXT, style TEXT, image TEXT, created_by TEXT, created_at TIMESTAMPTZ DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS encontros (id TEXT PRIMARY KEY, title TEXT NOT NULL, date DATE, location TEXT, created_at TIMESTAMPTZ DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS tastings (id TEXT PRIMARY KEY, beer_id TEXT REFERENCES beers(id) ON DELETE CASCADE,
    member_id TEXT REFERENCES members(id) ON DELETE CASCADE, encontro_id TEXT REFERENCES encontros(id) ON DELETE SET NULL,
    score REAL NOT NULL, notes TEXT, date DATE DEFAULT CURRENT_DATE)`;
  await sql`CREATE TABLE IF NOT EXISTS attendance (encontro_id TEXT REFERENCES encontros(id) ON DELETE CASCADE,
    member_id TEXT REFERENCES members(id) ON DELETE CASCADE, status TEXT, PRIMARY KEY (encontro_id, member_id))`;
  await sql`ALTER TABLE beers ADD COLUMN IF NOT EXISTS created_by TEXT`;
  await sql`ALTER TABLE tastings ADD COLUMN IF NOT EXISTS encontro_id TEXT`;

  // Tesouraria (v4)
  await sql`CREATE TABLE IF NOT EXISTS stock_items (id TEXT PRIMARY KEY, kind TEXT NOT NULL DEFAULT 'cerveja', name TEXT NOT NULL,
    unit TEXT, qty NUMERIC(12,2) NOT NULL DEFAULT 0, unit_cost NUMERIC(12,2) NOT NULL DEFAULT 0, sale_price NUMERIC(12,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS fin_entries (id TEXT PRIMARY KEY, kind TEXT NOT NULL, category TEXT, description TEXT,
    amount NUMERIC(12,2) NOT NULL DEFAULT 0, method TEXT, status TEXT NOT NULL DEFAULT 'pago',
    entry_date DATE DEFAULT CURRENT_DATE, due_date DATE, origin TEXT NOT NULL DEFAULT 'manual',
    item_id TEXT, encontro_id TEXT REFERENCES encontros(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS stock_moves (id TEXT PRIMARY KEY, item_id TEXT REFERENCES stock_items(id) ON DELETE SET NULL,
    type TEXT, qty NUMERIC(12,2) NOT NULL DEFAULT 0, unit_value NUMERIC(12,2) DEFAULT 0, cost_value NUMERIC(12,2),
    fin_entry_id TEXT, created_at TIMESTAMPTZ DEFAULT now())`;

  if(needV2){
    const ph=hashPass(SEED_PW);
    for(const m of SEED.members) await sql`INSERT INTO members (id,name,pass_hash) VALUES (${m.id},${m.name},${ph}) ON CONFLICT (id) DO NOTHING`;
    for(const b of SEED.beers) await sql`INSERT INTO beers (id,name,brewery,style) VALUES (${b.id},${b.name},${b.brewery},${b.style}) ON CONFLICT (id) DO NOTHING`;
    for(const t of SEED.tastings) await sql`INSERT INTO tastings (id,beer_id,member_id,score,notes,date) VALUES (${randomUUID()},${t.beer},${t.m},${t.s},${t.n},CURRENT_DATE)`;
    await sql`INSERT INTO encontros (id,title,date,location) VALUES ('e1','Concílio de Fevereiro', CURRENT_DATE - 20, 'Taverna do Pônei Saltitante')`;
    await sql`INSERT INTO encontros (id,title,date,location) VALUES ('e2','Conselho de Março', CURRENT_DATE + 14, 'Salão do Dragão Verde')`;
    for(const m of ['m1','m2','m3']) await sql`INSERT INTO attendance (encontro_id,member_id,status) VALUES ('e2',${m},'sim') ON CONFLICT DO NOTHING`;
    await sql`UPDATE tastings SET encontro_id='e1' WHERE encontro_id IS NULL`;
    // tesouraria de exemplo
    await sql`INSERT INTO stock_items (id,kind,name,unit,qty,unit_cost,sale_price) VALUES ('si1','cerveja','Stout do Condado','garrafa',12,9.00,16.00)`;
    await sql`INSERT INTO stock_items (id,kind,name,unit,qty,unit_cost,sale_price) VALUES ('si2','porcao','Tábua de Frios','porção',0,25.00,40.00)`;
    await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,origin) VALUES (${randomUUID()},'aporte','Aporte de membro','Aporte inicial dos confrades',300.00,'Pix','pago','manual')`;
    await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,origin) VALUES (${randomUUID()},'despesa','Compra de cerveja','12 garrafa de Stout do Condado',108.00,'Pix','pago','manual')`;
    await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,due_date,origin) VALUES (${randomUUID()},'despesa','Aluguel do espaço','Aluguel do salão do próximo encontro',120.00,'Transferência','pendente',CURRENT_DATE + 10,'manual')`;
  }

  if(needV2||needV3||needV4) await sql`INSERT INTO meta (k,v) VALUES ('schema_version','4') ON CONFLICT (k) DO UPDATE SET v='4'`;
}

async function readState(){
  const members=await sql`SELECT id,name FROM members ORDER BY name ASC`;
  const beers=await sql`SELECT id,name,brewery,style,image,created_by FROM beers ORDER BY name ASC`;
  const encontros=await sql`SELECT id,title,to_char(date,'YYYY-MM-DD') AS date,location FROM encontros ORDER BY date DESC`;
  const trows=await sql`SELECT id,beer_id,member_id,encontro_id,score,notes,to_char(date,'YYYY-MM-DD') AS date FROM tastings ORDER BY date DESC, id DESC`;
  const att=await sql`SELECT encontro_id,member_id,status FROM attendance`;
  return {
    members,
    beers: beers.map(b=>({id:b.id,name:b.name,brewery:b.brewery,style:b.style,image:b.image,createdBy:b.created_by})),
    encontros,
    tastings: trows.map(t=>({id:t.id,beerId:t.beer_id,memberId:t.member_id,encontroId:t.encontro_id,score:Number(t.score),notes:t.notes,date:t.date})),
    attendance: att.map(a=>({encontroId:a.encontro_id,memberId:a.member_id,status:a.status})),
  };
}

async function readFin(){
  const items=await sql`SELECT id,kind,name,unit,qty,unit_cost,sale_price FROM stock_items ORDER BY kind ASC, name ASC`;
  const entries=await sql`SELECT id,kind,category,description,amount,method,status,to_char(entry_date,'YYYY-MM-DD') AS date,to_char(due_date,'YYYY-MM-DD') AS due_date,origin,item_id FROM fin_entries ORDER BY entry_date DESC NULLS LAST, created_at DESC, id DESC`;
  const moves=await sql`SELECT id,item_id,type,qty,unit_value,cost_value,to_char(created_at,'YYYY-MM-DD') AS date FROM stock_moves ORDER BY created_at DESC, id DESC`;
  return {
    items: items.map(i=>({id:i.id,kind:i.kind,name:i.name,unit:i.unit,qty:Number(i.qty),unitCost:Number(i.unit_cost),salePrice:Number(i.sale_price)})),
    entries: entries.map(e=>({id:e.id,kind:e.kind,category:e.category,description:e.description,amount:Number(e.amount),method:e.method,status:e.status,date:e.date,dueDate:e.due_date,origin:e.origin,itemId:e.item_id})),
    moves: moves.map(m=>({id:m.id,itemId:m.item_id,type:m.type,qty:Number(m.qty),unitValue:Number(m.unit_value),costValue:m.cost_value==null?null:Number(m.cost_value)})),
  };
}

async function getBody(req){ if(req.body&&typeof req.body==='object') return req.body;
  return await new Promise((res,rej)=>{ let r=''; req.on('data',c=>r+=c); req.on('end',()=>{try{res(r?JSON.parse(r):{});}catch(e){rej(e);}}); req.on('error',rej); }); }
const clean=v=>(typeof v==='string'?v.trim():v);
const money=v=>{ const n=Number(v); return (isFinite(n)&&n>=0)?Math.round(n*100)/100:NaN; };
const qtyNum=v=>{ const n=Number(v); return isFinite(n)?Math.round(n*100)/100:NaN; };

export default async function handler(req,res){
  if(!sql) return res.status(500).json({error:'Banco não conectado. Conecte um Postgres (Neon) ao projeto no Vercel.'});
  try{
    await ensureSetup();
    const body=req.method==='POST'?await getBody(req):{};
    const action=body.action; const payload=body.payload||{};

    if(req.method==='POST'&&action==='loginAdmin'){
      if(!ADMIN_PASSWORD) return res.status(500).json({error:'ADMIN_PASSWORD não configurada no Vercel.'});
      if(String(payload.password||'')!==ADMIN_PASSWORD) return res.status(401).json({error:'Senha de administrador incorreta.'});
      return res.status(200).json({token:makeToken({sub:'admin',role:'admin',name:'Administrador'}),me:{role:'admin',name:'Administrador'}});
    }
    if(req.method==='POST'&&action==='loginMember'){
      const name=clean(payload.name);
      const rows=await sql`SELECT id,name,pass_hash FROM members WHERE lower(name)=lower(${name})`;
      if(rows.length===0||!verifyPass(payload.password,rows[0].pass_hash)) return res.status(401).json({error:'Nome ou senha incorretos.'});
      const m=rows[0];
      return res.status(200).json({token:makeToken({sub:m.id,role:'member',name:m.name}),me:{id:m.id,role:'member',name:m.name}});
    }

    const auth=verifyToken(bearer(req));
    if(!auth) return res.status(401).json({error:'Sessão expirada ou ausente. Entre novamente.'});
    const isAdmin=auth.role==='admin';

    if(req.method==='GET') return res.status(200).json(await readState());

    if(req.method==='POST'){
      if(action==='addMember'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode cadastrar confrades.'});
        const name=clean(payload.name), pw=String(payload.password||'');
        if(!name) return res.status(400).json({error:'Informe o nome do confrade.'});
        if(pw.length<4) return res.status(400).json({error:'A senha deve ter ao menos 4 caracteres.'});
        const ex=await sql`SELECT 1 FROM members WHERE lower(name)=lower(${name})`;
        if(ex.length) return res.status(400).json({error:'Já existe um confrade com esse nome.'});
        await sql`INSERT INTO members (id,name,pass_hash) VALUES (${randomUUID()},${name},${hashPass(pw)})`;

      } else if(action==='setPassword'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode redefinir senhas.'});
        const pw=String(payload.password||''); if(pw.length<4) return res.status(400).json({error:'A senha deve ter ao menos 4 caracteres.'});
        await sql`UPDATE members SET pass_hash=${hashPass(pw)} WHERE id=${String(payload.id||'')}`;

      } else if(action==='deleteMember'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode remover confrades.'});
        await sql`DELETE FROM members WHERE id=${String(payload.id||'')}`;

      } else if(action==='addBeer'){
        const name=clean(payload.name); if(!name) return res.status(400).json({error:'Dê um nome à cerveja.'});
        let img=payload.image||null;
        if(img&&(typeof img!=='string'||img.length>600000)) return res.status(400).json({error:'Imagem muito grande. Use uma foto menor.'});
        const by=auth.role==='member'?auth.sub:null;
        await sql`INSERT INTO beers (id,name,brewery,style,image,created_by) VALUES (${randomUUID()},${name},${clean(payload.brewery)||null},${clean(payload.style)||null},${img},${by})`;

      } else if(action==='deleteBeer'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode remover cervejas.'});
        await sql`DELETE FROM beers WHERE id=${String(payload.id||'')}`;

      } else if(action==='addTasting'){
        if(auth.role!=='member') return res.status(403).json({error:'Entre como confrade para registrar degustações.'});
        const beerId=String(payload.beerId||''), score=Number(payload.score);
        const encontroId=payload.encontroId?String(payload.encontroId):null;
        const beer=await sql`SELECT 1 FROM beers WHERE id=${beerId}`; if(!beer.length) return res.status(400).json({error:'Escolha uma cerveja do catálogo.'});
        if(!(score>=0&&score<=10)) return res.status(400).json({error:'Nota inválida.'});
        if(encontroId){ const e=await sql`SELECT 1 FROM encontros WHERE id=${encontroId}`; if(!e.length) return res.status(400).json({error:'Encontro inválido.'}); }
        await sql`INSERT INTO tastings (id,beer_id,member_id,encontro_id,score,notes,date) VALUES (${randomUUID()},${beerId},${auth.sub},${encontroId},${score},${clean(payload.notes)||null},CURRENT_DATE)`;

      } else if(action==='deleteTasting'){
        const id=String(payload.id||'');
        if(isAdmin) await sql`DELETE FROM tastings WHERE id=${id}`;
        else await sql`DELETE FROM tastings WHERE id=${id} AND member_id=${auth.sub}`;

      } else if(action==='addEncontro'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode agendar encontros.'});
        const title=clean(payload.title); if(!title) return res.status(400).json({error:'Dê um título ao encontro.'});
        await sql`INSERT INTO encontros (id,title,date,location) VALUES (${randomUUID()},${title},${payload.date||null},${clean(payload.location)||null})`;

      } else if(action==='updateEncontro'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode editar encontros.'});
        const title=clean(payload.title); if(!title) return res.status(400).json({error:'Dê um título ao encontro.'});
        await sql`UPDATE encontros SET title=${title}, date=${payload.date||null}, location=${clean(payload.location)||null} WHERE id=${String(payload.id||'')}`;

      } else if(action==='deleteEncontro'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador pode remover encontros.'});
        await sql`DELETE FROM encontros WHERE id=${String(payload.id||'')}`;

      } else if(action==='rsvp'){
        if(auth.role!=='member') return res.status(403).json({error:'Entre como confrade para confirmar presença.'});
        const eid=String(payload.encontroId||''); const st=String(payload.status||'');
        if(['sim','talvez','nao'].indexOf(st)<0) return res.status(400).json({error:'Status inválido.'});
        const e=await sql`SELECT 1 FROM encontros WHERE id=${eid}`; if(!e.length) return res.status(400).json({error:'Encontro inválido.'});
        await sql`INSERT INTO attendance (encontro_id,member_id,status) VALUES (${eid},${auth.sub},${st})
                  ON CONFLICT (encontro_id,member_id) DO UPDATE SET status=EXCLUDED.status`;

      /* ----------------- TESOURARIA (admin) ----------------- */
      } else if(action==='finState'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        return res.status(200).json(await readFin());

      } else if(action==='finAdd'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const kind=['receita','despesa','aporte'].indexOf(payload.kind)>=0?payload.kind:'despesa';
        const amount=money(payload.amount); if(isNaN(amount)||amount<=0) return res.status(400).json({error:'Informe um valor válido.'});
        const status=payload.status==='pendente'?'pendente':'pago';
        await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,entry_date,due_date,origin)
          VALUES (${randomUUID()},${kind},${clean(payload.category)||null},${clean(payload.description)||null},${amount},${clean(payload.method)||null},${status},${payload.date||null},${payload.dueDate||null},'manual')`;
        return res.status(200).json(await readFin());

      } else if(action==='finSetStatus'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const st=payload.status==='pendente'?'pendente':'pago';
        await sql`UPDATE fin_entries SET status=${st} WHERE id=${String(payload.id||'')}`;
        return res.status(200).json(await readFin());

      } else if(action==='finDelete'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        await sql`DELETE FROM fin_entries WHERE id=${String(payload.id||'')}`;
        return res.status(200).json(await readFin());

      } else if(action==='stockAdd'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const name=clean(payload.name); if(!name) return res.status(400).json({error:'Dê um nome ao item.'});
        const kind=['cerveja','porcao','insumo','outro'].indexOf(payload.kind)>=0?payload.kind:'cerveja';
        const uc=money(payload.unitCost), sp=money(payload.salePrice), qty=qtyNum(payload.qty!=null?payload.qty:0);
        if(isNaN(uc)||isNaN(sp)||isNaN(qty)) return res.status(400).json({error:'Valores inválidos.'});
        await sql`INSERT INTO stock_items (id,kind,name,unit,qty,unit_cost,sale_price) VALUES (${randomUUID()},${kind},${name},${clean(payload.unit)||null},${qty},${uc},${sp})`;
        return res.status(200).json(await readFin());

      } else if(action==='stockUpdate'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const name=clean(payload.name); if(!name) return res.status(400).json({error:'Dê um nome ao item.'});
        const kind=['cerveja','porcao','insumo','outro'].indexOf(payload.kind)>=0?payload.kind:'cerveja';
        const uc=money(payload.unitCost), sp=money(payload.salePrice);
        if(isNaN(uc)||isNaN(sp)) return res.status(400).json({error:'Valores inválidos.'});
        await sql`UPDATE stock_items SET name=${name}, kind=${kind}, unit_cost=${uc}, sale_price=${sp} WHERE id=${String(payload.id||'')}`;
        return res.status(200).json(await readFin());

      } else if(action==='stockDelete'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        await sql`DELETE FROM stock_items WHERE id=${String(payload.id||'')}`;
        return res.status(200).json(await readFin());

      } else if(action==='stockBuy'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const itemId=String(payload.itemId||''); const it=await sql`SELECT * FROM stock_items WHERE id=${itemId}`;
        if(!it.length) return res.status(400).json({error:'Item de estoque inválido.'});
        const qty=qtyNum(payload.qty), uc=money(payload.unitCost);
        if(isNaN(qty)||qty<=0||isNaN(uc)) return res.status(400).json({error:'Quantidade e custo precisam ser válidos.'});
        const i=it[0]; const total=Math.round(qty*uc*100)/100;
        const status=payload.status==='pendente'?'pendente':'pago';
        const lab={cerveja:'cerveja',porcao:'porção',insumo:'insumo',outro:'item'}[i.kind]||'item';
        const desc=`${qty} ${i.unit||'un'} de ${i.name}`;
        const finId=randomUUID();
        await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,entry_date,due_date,origin,item_id)
          VALUES (${finId},'despesa',${'Compra de '+lab},${desc},${total},${clean(payload.method)||null},${status},${payload.date||null},${payload.dueDate||null},'auto',${itemId})`;
        await sql`INSERT INTO stock_moves (id,item_id,type,qty,unit_value,cost_value,fin_entry_id) VALUES (${randomUUID()},${itemId},'compra',${qty},${uc},NULL,${finId})`;
        await sql`UPDATE stock_items SET qty=qty+${qty}, unit_cost=${uc} WHERE id=${itemId}`;
        return res.status(200).json(await readFin());

      } else if(action==='stockSell'){
        if(!isAdmin) return res.status(403).json({error:'Apenas o administrador acessa a tesouraria.'});
        const itemId=String(payload.itemId||''); const it=await sql`SELECT * FROM stock_items WHERE id=${itemId}`;
        if(!it.length) return res.status(400).json({error:'Item de estoque inválido.'});
        const qty=qtyNum(payload.qty); let up=money(payload.unitPrice);
        if(isNaN(qty)||qty<=0) return res.status(400).json({error:'Quantidade inválida.'});
        const i=it[0]; if(isNaN(up)) up=Number(i.sale_price);
        const cost=Number(i.unit_cost); const total=Math.round(qty*up*100)/100;
        const status=payload.status==='pendente'?'pendente':'pago';
        const lab={cerveja:'cerveja',porcao:'porção',insumo:'insumo',outro:'item'}[i.kind]||'item';
        const desc=`${qty} ${i.unit||'un'} de ${i.name}`;
        const finId=randomUUID();
        await sql`INSERT INTO fin_entries (id,kind,category,description,amount,method,status,entry_date,origin,item_id)
          VALUES (${finId},'receita',${'Venda de '+lab},${desc},${total},${clean(payload.method)||null},${status},${payload.date||null},'auto',${itemId})`;
        await sql`INSERT INTO stock_moves (id,item_id,type,qty,unit_value,cost_value,fin_entry_id) VALUES (${randomUUID()},${itemId},'venda',${qty},${up},${cost},${finId})`;
        if(i.kind!=='porcao') await sql`UPDATE stock_items SET qty=qty-${qty} WHERE id=${itemId}`;
        return res.status(200).json(await readFin());

      } else {
        return res.status(400).json({error:'Ação desconhecida.'});
      }
      return res.status(200).json(await readState());
    }
    return res.status(405).json({error:'Método não permitido.'});
  }catch(e){ return res.status(500).json({error:String((e&&e.message)||e)}); }
}
