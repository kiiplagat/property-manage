const express = require('express'), Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const db = new Database('stb.db');
db.exec(`
create table if not exists users(id integer primary key, name text, username text unique, hash text, role text, property_id integer);
create table if not exists properties(id integer primary key, name text, location text);
create table if not exists units(id integer primary key, property_id integer, number text, rent real);
create table if not exists tenants(id integer primary key, user_id integer, name text, phone text, id_number text, unit_id integer, move_in text, deposit real default 0);
create table if not exists payments(id integer primary key, tenant_id integer, amount real, method text, note text, date text default (date('now')), recorded_by integer);
create table if not exists complaints(id integer primary key, tenant_id integer, title text, description text, status text default 'open', comment text, created_at text default (datetime('now')));
`);

const app = express();
app.use(express.json(), express.static(path.join(__dirname, 'public'))); 
const wrap = f => (q, s) => { try { f(q, s); } catch (e) { s.status(400).json({ error: e.message }); } };
const auth = (...roles) => (q, s, next) => {
  try { q.user = jwt.verify((q.headers.authorization || '').slice(7), SECRET); }
  catch { return s.status(401).json({ error: 'Please log in' }); }
  if (roles.length && !roles.includes(q.user.role)) return s.status(403).json({ error: 'Not allowed for your role' });
  next();
};
const need = (o, ...k) => k.forEach(x => { if (!o[x]) throw new Error(x + ' is required'); });
const mkUser = (name, username, password, role, property_id = null) => {
  need({ name, username, password }, 'name', 'username', 'password');
  return db.prepare('insert into users(name,username,hash,role,property_id) values(?,?,?,?,?)')
    .run(name, username, bcrypt.hashSync(password, 10), role, property_id).lastInsertRowid;
};

// ---- Auth ----
app.post('/api/register', wrap((q, s) => { // first landlord only
  if (db.prepare("select 1 from users where role='landlord'").get()) throw new Error('Landlord account already exists');
  mkUser(q.body.name, q.body.username, q.body.password, 'landlord'); s.json({ ok: true });
}));
app.post('/api/login', wrap((q, s) => {
  const u = db.prepare('select * from users where username=?').get(q.body.username);
  if (!u || !bcrypt.compareSync(q.body.password || '', u.hash)) throw new Error('Wrong username or password');
  const user = { id: u.id, name: u.name, role: u.role, property_id: u.property_id };
  s.json({ token: jwt.sign(user, SECRET, { expiresIn: '7d' }), user });
}));

// ---- Helpers ----
const balance = t => {
  if (!t.unit_id) return 0;
  const a = new Date(t.move_in), n = new Date();
 // Move-in month is charged at move-in; each later month is charged once its 5th has arrived
let diff = (n.getFullYear() - a.getFullYear()) * 12 + n.getMonth() - a.getMonth();
if (n.getDate() < 5) diff -= 1;
const months = 1 + Math.max(0, diff);
  const paid = db.prepare('select coalesce(sum(amount),0) s from payments where tenant_id=?').get(t.id).s;
  return months * (t.rent || 0) - paid; // positive = owes
};
const TQ = 'select t.*, u.number unit, u.rent, u.property_id from tenants t left join units u on u.id=t.unit_id';
const scope = (user, rows) => user.role === 'caretaker' ? rows.filter(r => r.property_id === user.property_id) : rows;
const myTenant = user => db.prepare(TQ + ' where t.user_id=?').get(user.id);

// ---- Properties & units ----
app.get('/api/properties', auth('landlord', 'caretaker'), (q, s) => {
  const r = db.prepare('select * from properties').all();
  s.json(q.user.role === 'caretaker' ? r.filter(p => p.id === q.user.property_id) : r);
});
app.post('/api/properties', auth('landlord'), wrap((q, s) => {
  need(q.body, 'name'); db.prepare('insert into properties(name,location) values(?,?)').run(q.body.name, q.body.location || ''); s.json({ ok: true });
}));
app.get('/api/units', auth('landlord', 'caretaker'), (q, s) => s.json(scope(q.user, db.prepare(
  'select u.*, p.name property, t.name tenant from units u join properties p on p.id=u.property_id left join tenants t on t.unit_id=u.id').all())));
app.post('/api/units', auth('landlord'), wrap((q, s) => {
  need(q.body, 'property_id', 'number', 'rent');
  db.prepare('insert into units(property_id,number,rent) values(?,?,?)').run(q.body.property_id, q.body.number, +q.body.rent); s.json({ ok: true });
}));

// ---- Tenants ----
app.get('/api/tenants', auth('landlord', 'caretaker'), (q, s) =>
  s.json(scope(q.user, db.prepare(TQ).all()).map(t => ({ ...t, balance: balance(t) }))));
app.post('/api/tenants', auth('landlord'), wrap((q, s) => {
  const b = q.body; need(b, 'name', 'phone', 'unit_id', 'move_in', 'username', 'password');
  if (db.prepare('select 1 from tenants where unit_id=?').get(b.unit_id)) throw new Error('That unit is already occupied');
  const uid = mkUser(b.name, b.username, b.password, 'tenant');
  db.prepare('insert into tenants(user_id,name,phone,id_number,unit_id,move_in,deposit) values(?,?,?,?,?,?,?)')
    .run(uid, b.name, b.phone, b.id_number || '', b.unit_id, b.move_in, +b.deposit || 0); s.json({ ok: true });
}));
app.delete('/api/tenants/:id', auth('landlord'), wrap((q, s) => {
  const t = db.prepare('select * from tenants where id=?').get(q.params.id); if (!t) throw new Error('Not found');
  db.prepare('delete from tenants where id=?').run(t.id); db.prepare('delete from users where id=?').run(t.user_id); s.json({ ok: true });
}));

// ---- Caretakers ----
app.get('/api/caretakers', auth('landlord'), (q, s) => s.json(db.prepare(
  "select u.id,u.name,u.username,p.name property from users u left join properties p on p.id=u.property_id where role='caretaker'").all()));
app.post('/api/caretakers', auth('landlord'), wrap((q, s) => {
  need(q.body, 'property_id'); mkUser(q.body.name, q.body.username, q.body.password, 'caretaker', +q.body.property_id); s.json({ ok: true });
}));
app.delete('/api/caretakers/:id', auth('landlord'), (q, s) => { db.prepare("delete from users where id=? and role='caretaker'").run(q.params.id); s.json({ ok: true }); });

// ---- Payments (caretakers may record, not delete or edit) ----
app.get('/api/payments', auth('landlord', 'caretaker'), (q, s) => s.json(scope(q.user, db.prepare(
  'select p.*, t.name tenant, u.number unit, u.property_id from payments p join tenants t on t.id=p.tenant_id left join units u on u.id=t.unit_id order by p.id desc').all())));
app.post('/api/payments', auth('landlord', 'caretaker'), wrap((q, s) => {
  need(q.body, 'tenant_id', 'amount');
  const t = db.prepare(TQ + ' where t.id=?').get(q.body.tenant_id);
  if (!t || (q.user.role === 'caretaker' && t.property_id !== q.user.property_id)) throw new Error('Tenant not in your property');
  db.prepare('insert into payments(tenant_id,amount,method,note,recorded_by) values(?,?,?,?,?)')
    .run(t.id, +q.body.amount, q.body.method || 'cash', q.body.note || '', q.user.id); s.json({ ok: true });
}));
app.delete('/api/payments/:id', auth('landlord'), (q, s) => { db.prepare('delete from payments where id=?').run(q.params.id); s.json({ ok: true }); });

// ---- Complaints ----
const CQ = 'select c.*, t.name tenant, u.number unit, u.property_id from complaints c join tenants t on t.id=c.tenant_id left join units u on u.id=t.unit_id order by c.id desc';
app.get('/api/complaints', auth(), (q, s) => {
  if (q.user.role === 'tenant') { const t = myTenant(q.user); return s.json(db.prepare('select * from complaints where tenant_id=? order by id desc').all(t.id)); }
  s.json(scope(q.user, db.prepare(CQ).all()));
});
app.post('/api/complaints', auth('tenant'), wrap((q, s) => {
  need(q.body, 'title'); db.prepare('insert into complaints(tenant_id,title,description) values(?,?,?)')
    .run(myTenant(q.user).id, q.body.title, q.body.description || ''); s.json({ ok: true });
}));
app.patch('/api/complaints/:id', auth('landlord', 'caretaker'), wrap((q, s) => {
  const c = scope(q.user, db.prepare(CQ).all()).find(x => x.id == q.params.id); if (!c) throw new Error('Complaint not found');
  db.prepare('update complaints set status=?, comment=? where id=?').run(q.body.status || c.status, q.body.comment ?? c.comment, c.id); s.json({ ok: true });
}));

// ---- Tenant self view & landlord summary ----
app.get('/api/me', auth('tenant'), (q, s) => {
  const t = myTenant(q.user);
  s.json({ ...t, balance: balance(t), payments: db.prepare('select * from payments where tenant_id=? order by id desc').all(t.id) });
});
app.get('/api/summary', auth('landlord'), (q, s) => {
  const ts = db.prepare(TQ).all();
  s.json({
    units: db.prepare('select count(*) n from units').get().n, tenants: ts.length,
    collected: db.prepare("select coalesce(sum(amount),0) s from payments where strftime('%Y-%m',date)=strftime('%Y-%m','now')").get().s,
    arrears: ts.reduce((a, t) => a + Math.max(0, balance(t)), 0),
    openComplaints: db.prepare("select count(*) n from complaints where status!='resolved'").get().n
  });
});

app.listen(process.env.PORT || 3000, () => console.log('STB running on http://localhost:3000'));
