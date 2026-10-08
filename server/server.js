/* Kashf — Bahi Khata & Inventory Management System (backend) */
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, todayLocal, nowISO, r2, exportAll, importAll, autoBackup, seedIfNeeded, BACKUP_DIR } = require('./db');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kashf-dev-secret-change-me';
const app = express();
app.use(express.json({ limit: '25mb' }));

/* ---------- helpers ---------- */
function addDays(ymd, n) {
  const d = new Date(ymd + 'T00:00:00');
  d.setDate(d.getDate() + n);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
const sum = (sql, ...a) => Number(db.prepare(sql).get(...a)['v'] || 0);

/* ---------- auth ---------- */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: 'NO_TOKEN' });
  try {
    const p = jwt.verify(tok, JWT_SECRET);
    const u = db.prepare('SELECT id,name,username,role,shop_id,disabled FROM users WHERE id=?').get(p.id);
    if (!u || u.disabled) return res.status(403).json({ error: 'ACCOUNT_DISABLED' });
    req.user = u; next();
  } catch { return res.status(401).json({ error: 'BAD_TOKEN' }); }
}
const needAdmin = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'ADMIN_ONLY' });
const noDeleteForStaff = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'ADMIN_ONLY' });

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u || u.disabled || !bcrypt.compareSync(password || '', u.pass_hash))
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  const token = jwt.sign({ id: u.id, role: u.role, shop_id: u.shop_id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: u.id, name: u.name, username: u.username, role: u.role, shop_id: u.shop_id } });
});
app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

/* ---------- users (admin) ---------- */
app.get('/api/users', auth, needAdmin, (req, res) => {
  res.json(db.prepare('SELECT id,name,username,role,shop_id,disabled,created_at FROM users ORDER BY id').all());
});
app.post('/api/users', auth, needAdmin, (req, res) => {
  const { name, username, password, role, shop_id } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });
  if (!['admin', 'staff', 'shop'].includes(role)) return res.status(400).json({ error: 'BAD_ROLE' });
  if (role === 'shop' && !shop_id) return res.status(400).json({ error: 'SHOP_REQUIRED' });
  try {
    const r = db.prepare('INSERT INTO users (name,username,pass_hash,role,shop_id,created_at) VALUES (?,?,?,?,?,?)')
      .run(name, username, bcrypt.hashSync(password, 10), role, shop_id || null, nowISO());
    res.json({ id: r.lastInsertRowid });
  } catch { res.status(400).json({ error: 'USERNAME_TAKEN' }); }
});
app.put('/api/users/:id', auth, needAdmin, (req, res) => {
  const id = Number(req.params.id);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!u) return res.status(404).json({ error: 'NOT_FOUND' });
  const { name, password, role, shop_id, disabled } = req.body || {};
  if (id === req.user.id && (disabled === 1 || disabled === true))
    return res.status(400).json({ error: 'CANNOT_DISABLE_SELF' });
  if (u.role === 'admin' && role && role !== 'admin') {
    const c = db.prepare("SELECT COUNT(*) v FROM users WHERE role='admin' AND disabled=0 AND id<>?").get(id).v;
    if (!c) return res.status(400).json({ error: 'LAST_ADMIN' });
  }
  db.prepare(`UPDATE users SET name=COALESCE(?,name), role=COALESCE(?,role),
    shop_id=?, disabled=COALESCE(?,disabled) WHERE id=?`)
    .run(name ?? null, role ?? null, shop_id === undefined ? u.shop_id : shop_id,
      disabled === undefined ? null : (disabled ? 1 : 0), id);
  if (password) db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(bcrypt.hashSync(password, 10), id);
  res.json({ ok: true });
});
app.delete('/api/users/:id', auth, needAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: 'CANNOT_DELETE_SELF' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!u) return res.status(404).json({ error: 'NOT_FOUND' });
  if (u.role === 'admin') {
    const c = db.prepare("SELECT COUNT(*) v FROM users WHERE role='admin' AND id<>?").get(id).v;
    if (!c) return res.status(400).json({ error: 'LAST_ADMIN' });
  }
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  res.json({ ok: true });
});

/* ---------- shops / suppliers ---------- */
function crud(base, table, fields, { shopScoped = false } = {}) {
  app.get(base, auth, (req, res) => {
    if (req.user.role === 'shop') {
      if (!shopScoped) return res.status(403).json({ error: 'FORBIDDEN' });
      const r = db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(req.user.shop_id);
      return res.json(r ? [r] : []);
    }
    res.json(db.prepare(`SELECT * FROM ${table} ORDER BY id`).all());
  });
  app.post(base, auth, (req, res) => {
    if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
    const vals = fields.map((f) => req.body[f] ?? (f === 'disabled' ? 0 : ''));
    const r = db.prepare(`INSERT INTO ${table} (${fields.join(',')}) VALUES (${fields.map(() => '?').join(',')})`).run(...vals);
    res.json({ id: r.lastInsertRowid });
  });
  app.put(base + '/:id', auth, (req, res) => {
    if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
    const sets = fields.filter((f) => req.body[f] !== undefined);
    if (!sets.length) return res.json({ ok: true });
    db.prepare(`UPDATE ${table} SET ${sets.map((f) => `${f}=?`).join(',')} WHERE id=?`)
      .run(...sets.map((f) => req.body[f]), req.params.id);
    res.json({ ok: true });
  });
  app.delete(base + '/:id', auth, noDeleteForStaff, (req, res) => {
    db.prepare(`DELETE FROM ${table} WHERE id=?`).run(req.params.id);
    res.json({ ok: true });
  });
}
crud('/api/shops', 'shops', ['name', 'phone', 'address', 'whatsapp', 'disabled'], { shopScoped: true });
crud('/api/suppliers', 'suppliers', ['name', 'phone', 'address']);

/* ---------- products ---------- */
app.get('/api/products', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  res.json(db.prepare('SELECT * FROM products ORDER BY name_ur').all());
});
const PF = ['name_ur', 'name_en', 'sku', 'barcode', 'category', 'unit', 'purchase_rate', 'sale_rate', 'wholesale_rate', 'stock', 'low_threshold', 'disabled'];
app.post('/api/products', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  if (!req.body.name_ur) return res.status(400).json({ error: 'NAME_REQUIRED' });
  const vals = PF.map((f) => req.body[f] ?? (f === 'unit' ? 'کلو' : f === 'disabled' ? 0 : 0));
  const r = db.prepare(`INSERT INTO products (${PF.join(',')}) VALUES (${PF.map(() => '?').join(',')})`).run(...vals);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/products/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const sets = PF.filter((f) => req.body[f] !== undefined);
  if (sets.length) db.prepare(`UPDATE products SET ${sets.map((f) => `${f}=?`).join(',')} WHERE id=?`)
    .run(...sets.map((f) => req.body[f]), req.params.id);
  res.json({ ok: true });
});
app.delete('/api/products/:id', auth, noDeleteForStaff, (req, res) => {
  db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------- purchases ---------- */
function nextPurchaseBill() { return 'PUR-' + String(db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM purchases').get().n).padStart(4, '0'); }
app.get('/api/purchases', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31', supplier_id } = req.query;
  let sql = `SELECT p.*, s.name supplier_name FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id
             WHERE p.date BETWEEN ? AND ?`;
  const a = [from, to];
  if (supplier_id) { sql += ' AND p.supplier_id=?'; a.push(supplier_id); }
  res.json(db.prepare(sql + ' ORDER BY p.date DESC, p.id DESC').all(...a));
});
app.get('/api/purchases/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const p = db.prepare(`SELECT p.*, s.name supplier_name FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE p.id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'NOT_FOUND' });
  p.items = db.prepare(`SELECT pi.*, pr.name_ur, pr.unit FROM purchase_items pi JOIN products pr ON pr.id=pi.product_id WHERE pi.purchase_id=?`).all(p.id);
  res.json(p);
});
function applyPurchase(body, createdBy) {
  const { supplier_id, date, bill_no, items, bilty_amt = 0, bilty_paid_by = 'supplier', paid = 0, note = '' } = body;
  if (!supplier_id || !date || !Array.isArray(items) || !items.length) throw { status: 400, code: 'BAD_PURCHASE' };
  const sup = db.prepare('SELECT id FROM suppliers WHERE id=?').get(supplier_id);
  if (!sup) throw { status: 400, code: 'BAD_SUPPLIER' };
  const prods = {};
  for (const it of items) {
    const pr = db.prepare('SELECT * FROM products WHERE id=? AND disabled=0').get(it.product_id);
    if (!pr) throw { status: 400, code: 'BAD_PRODUCT' };
    if (!(it.qty > 0) || !(it.rate >= 0)) throw { status: 400, code: 'BAD_QTY_RATE' };
    prods[it.product_id] = pr;
  }
  const subtotal = r2(items.reduce((a, i) => a + i.qty * i.rate, 0));
  // Owner rule: supplier-paid bilty is NOT our cost. Only added if we paid it.
  const total = r2(subtotal + (bilty_paid_by === 'us' ? Number(bilty_amt) || 0 : 0));
  const balance = r2(total - (Number(paid) || 0));
  const id = db.prepare(`INSERT INTO purchases
    (supplier_id,date,bill_no,subtotal,bilty_amt,bilty_paid_by,total,paid,balance,note,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(supplier_id, date, bill_no || nextPurchaseBill(), subtotal, Number(bilty_amt) || 0,
      bilty_paid_by, total, Number(paid) || 0, balance, note, createdBy, nowISO()).lastInsertRowid;
  const pi = db.prepare('INSERT INTO purchase_items (purchase_id,product_id,qty,rate,amount) VALUES (?,?,?,?,?)');
  const ps = db.prepare('UPDATE products SET stock = stock + ? WHERE id=?');
  for (const it of items) { pi.run(id, it.product_id, it.qty, it.rate, r2(it.qty * it.rate)); ps.run(it.qty, it.product_id); }
  return id;
}
app.post('/api/purchases', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  db.exec('BEGIN');
  try { const id = applyPurchase(req.body, req.user.id); db.exec('COMMIT'); res.json({ id }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED' }); }
});
function revertPurchase(id) {
  const p = db.prepare('SELECT * FROM purchases WHERE id=?').get(id);
  if (!p) throw { status: 404, code: 'NOT_FOUND' };
  const items = db.prepare('SELECT * FROM purchase_items WHERE purchase_id=?').all(id);
  for (const it of items) {
    const pr = db.prepare('SELECT stock,name_ur FROM products WHERE id=?').get(it.product_id);
    if (pr.stock < it.qty) throw { status: 400, code: 'STOCK_WOULD_GO_NEGATIVE', product: pr.name_ur };
  }
  const ps = db.prepare('UPDATE products SET stock = stock - ? WHERE id=?');
  for (const it of items) ps.run(it.qty, it.product_id);
  db.prepare('DELETE FROM purchase_items WHERE purchase_id=?').run(id);
  db.prepare('DELETE FROM purchases WHERE id=?').run(id);
}
app.put('/api/purchases/:id', auth, needAdmin, (req, res) => {
  db.exec('BEGIN');
  try { revertPurchase(Number(req.params.id)); const id = applyPurchase(req.body, req.user.id); db.exec('COMMIT'); res.json({ id }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED', product: e.product }); }
});
app.delete('/api/purchases/:id', auth, noDeleteForStaff, (req, res) => {
  db.exec('BEGIN');
  try { revertPurchase(Number(req.params.id)); db.exec('COMMIT'); res.json({ ok: true }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED', product: e.product }); }
});

/* ---------- sales ---------- */
function nextSaleBill() { return 'KHF-' + String(db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM sales').get().n).padStart(4, '0'); }
app.get('/api/sales', auth, (req, res) => {
  const { from = '2000-01-01', to = '2999-12-31', shop_id, q } = req.query;
  let sql = `SELECT s.*, sh.name shop_name FROM sales s LEFT JOIN shops sh ON sh.id=s.shop_id WHERE s.date BETWEEN ? AND ?`;
  const a = [from, to];
  if (req.user.role === 'shop') { sql += ' AND s.shop_id=?'; a.push(req.user.shop_id); }
  else if (shop_id) { sql += ' AND s.shop_id=?'; a.push(shop_id); }
  if (q) { sql += ' AND (s.bill_no LIKE ? OR sh.name LIKE ?)'; a.push(`%${q}%`, `%${q}%`); }
  res.json(db.prepare(sql + ' ORDER BY s.date DESC, s.id DESC').all(...a));
});
app.get('/api/sales/:id', auth, (req, res) => {
  const s = db.prepare(`SELECT s.*, sh.name shop_name FROM sales s LEFT JOIN shops sh ON sh.id=s.shop_id WHERE s.id=?`).get(req.params.id);
  if (!s) return res.status(404).json({ error: 'NOT_FOUND' });
  if (req.user.role === 'shop' && s.shop_id !== req.user.shop_id) return res.status(403).json({ error: 'FORBIDDEN' });
  s.items = db.prepare(`SELECT si.*, pr.name_ur, pr.unit, pr.purchase_rate FROM sale_items si JOIN products pr ON pr.id=si.product_id WHERE si.sale_id=?`).all(s.id);
  s.expenses = db.prepare(`SELECT id, date, category, amount, note FROM expenses WHERE sale_id=? ORDER BY id`).all(s.id);
  res.json(s);
});
function applySale(body, createdBy, billNo) {
  const { date, customer_type = 'walkin', shop_id = null, items, discount = 0,
    paid = 0, payment_method = 'cash', note = '', manual_expenses = [] } = body;
  if (!date || !Array.isArray(items) || !items.length) throw { status: 400, code: 'BAD_SALE' };
  if (customer_type === 'shop') {
    if (!shop_id) throw { status: 400, code: 'SHOP_REQUIRED' };
    const sh = db.prepare('SELECT id FROM shops WHERE id=? AND disabled=0').get(shop_id);
    if (!sh) throw { status: 400, code: 'BAD_SHOP' };
  }
  for (const it of items) {
    const pr = db.prepare('SELECT * FROM products WHERE id=? AND disabled=0').get(it.product_id);
    if (!pr) throw { status: 400, code: 'BAD_PRODUCT' };
    if (!(it.qty > 0) || !(it.rate >= 0)) throw { status: 400, code: 'BAD_QTY_RATE' };
    if (pr.stock < it.qty) throw { status: 400, code: 'INSUFFICIENT_STOCK', product: pr.name_ur, available: pr.stock };
  }
  const subtotal = r2(items.reduce((a, i) => a + i.qty * i.rate, 0));
  // Owner rule (2026-10-08): bilty / petrol / other delivery expenses are OUR cost.
  // They are NEVER added to the customer bill. Staff adds them manually as
  // separate business expense entries linked to the bill, so the ledger shows
  // each one as its own clear line.
  const total = r2(subtotal - (Number(discount) || 0));
  const balance = r2(total - (Number(paid) || 0));
  const finalBillNo = billNo || nextSaleBill();
  const id = db.prepare(`INSERT INTO sales
    (bill_no,date,customer_type,shop_id,subtotal,bilty_amt,discount,expense_petrol,total,paid,balance,payment_method,note,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(finalBillNo, date, customer_type, customer_type === 'shop' ? shop_id : null,
      subtotal, 0, Number(discount) || 0, 0,
      total, Number(paid) || 0, balance, payment_method, note, createdBy, nowISO()).lastInsertRowid;
  const si = db.prepare('INSERT INTO sale_items (sale_id,product_id,qty,rate,amount) VALUES (?,?,?,?,?)');
  const ps = db.prepare('UPDATE products SET stock = stock - ? WHERE id=?');
  for (const it of items) { si.run(id, it.product_id, it.qty, it.rate, r2(it.qty * it.rate)); ps.run(it.qty, it.product_id); }
  // Manual expenses -> separate business expense entries linked to this bill
  if (Array.isArray(manual_expenses) && manual_expenses.length) {
    const ins = db.prepare(`INSERT INTO expenses (date,category,amount,note,kind,sale_id,created_by)
      VALUES (?,?,?,?,?,?,?)`);
    for (const e of manual_expenses) {
      const amt = Number(e.amount) || 0;
      const cat = String(e.category || '').trim();
      if (!(amt > 0) || !cat) throw { status: 400, code: 'BAD_MANUAL_EXPENSE' };
      const enote = [`بل نمبر ${finalBillNo}`, String(e.note || '').trim()].filter(Boolean).join(' — ');
      ins.run(date, cat, r2(amt), enote, 'business', id, createdBy);
    }
  }
  return id;
}
app.post('/api/sales', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  db.exec('BEGIN');
  try { const id = applySale(req.body, req.user.id); db.exec('COMMIT'); res.json({ id }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED', product: e.product, available: e.available }); }
});
function revertSale(id) {
  const s = db.prepare('SELECT * FROM sales WHERE id=?').get(id);
  if (!s) throw { status: 404, code: 'NOT_FOUND' };
  const ps = db.prepare('UPDATE products SET stock = stock + ? WHERE id=?');
  for (const it of db.prepare('SELECT * FROM sale_items WHERE sale_id=?').all(id)) ps.run(it.qty, it.product_id);
  db.prepare('DELETE FROM sale_items WHERE sale_id=?').run(id);
  db.prepare('DELETE FROM expenses WHERE sale_id=?').run(id); // linked manual expenses go with the bill
  db.prepare('DELETE FROM sales WHERE id=?').run(id);
  return s.bill_no;
}
app.put('/api/sales/:id', auth, needAdmin, (req, res) => {
  db.exec('BEGIN');
  try { const billNo = revertSale(Number(req.params.id)); const id = applySale(req.body, req.user.id, billNo); db.exec('COMMIT'); res.json({ id }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED', product: e.product, available: e.available }); }
});
app.delete('/api/sales/:id', auth, noDeleteForStaff, (req, res) => {
  db.exec('BEGIN');
  try { revertSale(Number(req.params.id)); db.exec('COMMIT'); res.json({ ok: true }); }
  catch (e) { db.exec('ROLLBACK'); res.status(e.status || 500).json({ error: e.code || 'FAILED' }); }
});

/* ---------- payments ---------- */
app.get('/api/payments', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31', party_type, party_id } = req.query;
  let sql = 'SELECT * FROM ledger_payments WHERE date BETWEEN ? AND ?'; const a = [from, to];
  if (party_type) { sql += ' AND party_type=?'; a.push(party_type); }
  if (party_id) { sql += ' AND party_id=?'; a.push(party_id); }
  res.json(db.prepare(sql + ' ORDER BY date DESC, id DESC').all(...a));
});
app.post('/api/payments', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { date, party_type, party_id, amount, method = 'cash', direction, note = '' } = req.body || {};
  if (!date || !['shop', 'supplier'].includes(party_type) || !party_id || !(amount > 0) || !['in', 'out'].includes(direction))
    return res.status(400).json({ error: 'BAD_PAYMENT' });
  const r = db.prepare(`INSERT INTO ledger_payments (date,party_type,party_id,amount,method,direction,note,created_by)
    VALUES (?,?,?,?,?,?,?,?)`).run(date, party_type, party_id, amount, method, direction, note, req.user.id);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/payments/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const f = ['date', 'amount', 'method', 'direction', 'note'].filter((k) => req.body[k] !== undefined);
  if (f.length) db.prepare(`UPDATE ledger_payments SET ${f.map((k) => `${k}=?`).join(',')} WHERE id=?`)
    .run(...f.map((k) => req.body[k]), req.params.id);
  res.json({ ok: true });
});
app.delete('/api/payments/:id', auth, noDeleteForStaff, (req, res) => {
  db.prepare('DELETE FROM ledger_payments WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------- expenses ---------- */
app.get('/api/expenses', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31', kind } = req.query;
  let sql = 'SELECT * FROM expenses WHERE date BETWEEN ? AND ?'; const a = [from, to];
  if (kind) { sql += ' AND kind=?'; a.push(kind); }
  res.json(db.prepare(sql + ' ORDER BY date DESC, id DESC').all(...a));
});
app.post('/api/expenses', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { date, category, amount, note = '', kind = 'business' } = req.body || {};
  if (!date || !category || !(amount > 0) || !['business', 'personal'].includes(kind))
    return res.status(400).json({ error: 'BAD_EXPENSE' });
  const r = db.prepare('INSERT INTO expenses (date,category,amount,note,kind,created_by) VALUES (?,?,?,?,?,?)')
    .run(date, category, amount, note, kind, req.user.id);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/expenses/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const f = ['date', 'category', 'amount', 'note', 'kind'].filter((k) => req.body[k] !== undefined);
  if (f.length) db.prepare(`UPDATE expenses SET ${f.map((k) => `${k}=?`).join(',')} WHERE id=?`)
    .run(...f.map((k) => req.body[k]), req.params.id);
  res.json({ ok: true });
});
app.delete('/api/expenses/:id', auth, noDeleteForStaff, (req, res) => {
  db.prepare('DELETE FROM expenses WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

/* ---------- dashboard & reports ---------- */
function pnl(from, to) {
  const revenue = r2(sum('SELECT SUM(subtotal-discount) v FROM sales WHERE date BETWEEN ? AND ?', from, to));
  const cogs = r2(sum(`SELECT SUM(si.qty*p.purchase_rate) v FROM sale_items si
    JOIN sales s ON s.id=si.sale_id JOIN products p ON p.id=si.product_id
    WHERE s.date BETWEEN ? AND ?`, from, to));
  const biz = r2(sum("SELECT SUM(amount) v FROM expenses WHERE kind='business' AND date BETWEEN ? AND ?", from, to));
  const per = r2(sum("SELECT SUM(amount) v FROM expenses WHERE kind='personal' AND date BETWEEN ? AND ?", from, to));
  const byCat = db.prepare(`SELECT category, SUM(amount) v FROM expenses
    WHERE kind='business' AND date BETWEEN ? AND ? GROUP BY category ORDER BY v DESC`).all(from, to);
  const gross = r2(revenue - cogs), net = r2(gross - biz), savings = r2(net - per);
  return { revenue, cogs, grossProfit: gross, businessExpenses: biz, personalExpenses: per, netProfit: net, savings, byCategory: byCat };
}
app.get('/api/dashboard/stats', auth, (req, res) => {
  const T = todayLocal();
  if (req.user.role === 'shop') {
    const sid = req.user.shop_id;
    const bal = r2(sum('SELECT SUM(total-paid) v FROM sales WHERE customer_type=\'shop\' AND shop_id=?', sid)
      - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='shop' AND party_id=? AND direction='in'", sid));
    const recent = db.prepare(`SELECT id,bill_no,date,total,paid,balance FROM sales
      WHERE shop_id=? ORDER BY date DESC, id DESC LIMIT 10`).all(sid);
    return res.json({ shop: true, balance: bal, recent });
  }
  const mStart = T.slice(0, 7) + '-01';
  const receivables = r2(sum("SELECT SUM(total-paid) v FROM sales WHERE customer_type='shop'")
    - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='shop' AND direction='in'"));
  const payables = r2(sum('SELECT SUM(total-paid) v FROM purchases')
    - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='supplier' AND direction='out'"));
  const lowStock = db.prepare('SELECT id,name_ur,name_en,stock,low_threshold,unit FROM products WHERE disabled=0 AND stock<=low_threshold ORDER BY stock').all();
  const wk = [];
  for (let i = 6; i >= 0; i--) {
    const d = addDays(T, -i);
    const rev = r2(sum('SELECT SUM(subtotal-discount) v FROM sales WHERE date=?', d));
    const cogs = r2(sum(`SELECT SUM(si.qty*p.purchase_rate) v FROM sale_items si
      JOIN sales s ON s.id=si.sale_id JOIN products p ON p.id=si.product_id WHERE s.date=?`, d));
    const exp = r2(sum("SELECT SUM(amount) v FROM expenses WHERE kind='business' AND date=?", d));
    wk.push({ date: d, revenue: rev, expenses: exp, profit: r2(rev - cogs - exp) });
  }
  const mp = pnl(mStart, T);
  res.json({
    todaySales: r2(sum('SELECT SUM(total) v FROM sales WHERE date=?', T)),
    weeklySales: r2(sum('SELECT SUM(total) v FROM sales WHERE date BETWEEN ? AND ?', addDays(T, -6), T)),
    monthlyTurnover: r2(sum('SELECT SUM(total) v FROM sales WHERE date BETWEEN ? AND ?', mStart, T)),
    receivables, payables, lowStock,
    netProfit: mp.netProfit, savings: mp.savings,
    weekly: wk,
  });
});
app.get('/api/reports/pnl', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31' } = req.query;
  res.json({ from, to, ...pnl(from, to) });
});
app.get('/api/reports/ledger', auth, (req, res) => {
  let { party_type, party_id, from = '2000-01-01', to = '2999-12-31' } = req.query;
  if (!['shop', 'supplier'].includes(party_type) || !party_id) return res.status(400).json({ error: 'BAD_PARTY' });
  party_id = Number(party_id);
  if (req.user.role === 'shop') {
    if (party_type !== 'shop' || party_id !== req.user.shop_id) return res.status(403).json({ error: 'FORBIDDEN' });
  }
  const evts = [];
  if (party_type === 'shop') {
    for (const s of db.prepare(`SELECT date,bill_no,total FROM sales WHERE customer_type='shop' AND shop_id=? ORDER BY date,id`).all(party_id))
      evts.push({ date: s.date, desc: `بل ${s.bill_no}`, debit: s.total, credit: 0 });
    for (const p of db.prepare(`SELECT date,amount,method,note FROM ledger_payments WHERE party_type='shop' AND party_id=? AND direction='in' ORDER BY date,id`).all(party_id))
      evts.push({ date: p.date, desc: `وصولی (${p.method})${p.note ? ' — ' + p.note : ''}`, debit: 0, credit: p.amount });
  } else {
    for (const p of db.prepare('SELECT date,bill_no,total FROM purchases WHERE supplier_id=? ORDER BY date,id').all(party_id))
      evts.push({ date: p.date, desc: `خرید ${p.bill_no}`, debit: 0, credit: p.total });
    for (const p of db.prepare(`SELECT date,amount,method,note FROM ledger_payments WHERE party_type='supplier' AND party_id=? AND direction='out' ORDER BY date,id`).all(party_id))
      evts.push({ date: p.date, desc: `ادائیگی (${p.method})${p.note ? ' — ' + p.note : ''}`, debit: p.amount, credit: 0 });
  }
  let bal = 0, opening = 0; const rows = [];
  for (const e of evts) {
    bal = r2(party_type === 'shop' ? bal + e.debit - e.credit : bal + e.credit - e.debit);
    if (e.date < from) opening = bal;
    else if (e.date <= to) rows.push({ ...e, balance: bal });
  }
  res.json({ party_type, party_id, from, to, opening, rows, closing: rows.length ? rows[rows.length - 1].balance : opening });
});
app.get('/api/reports/cashsales', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31', q = '' } = req.query;
  const rows = db.prepare(`SELECT s.id,s.bill_no,s.date,s.total,s.payment_method,COALESCE(sh.name,'') shop_name,
    (SELECT GROUP_CONCAT(p.name_ur||' '||si.qty||'x'||si.rate, '، ') FROM sale_items si JOIN products p ON p.id=si.product_id WHERE si.sale_id=s.id) items,
    (SELECT SUM(si.qty*(si.rate-p.purchase_rate)) FROM sale_items si JOIN products p ON p.id=si.product_id WHERE si.sale_id=s.id) margin
    FROM sales s LEFT JOIN shops sh ON sh.id=s.shop_id
    WHERE s.payment_method IN ('cash','easypaisa') AND s.date BETWEEN ? AND ?
    ORDER BY s.date DESC, s.id DESC`).all(from, to);
  const qq = q.trim();
  res.json(qq ? rows.filter((r) => (r.bill_no + r.items + r.shop_name).includes(qq)) : rows);
});

/* ---------- backup ---------- */
app.get('/api/backup/export', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  res.setHeader('Content-Disposition', `attachment; filename="kashf-backup-${todayLocal()}.json"`);
  res.json(exportAll());
});
app.post('/api/backup/import', auth, needAdmin, (req, res) => {
  try { importAll(req.body.data || req.body); res.json({ ok: true }); }
  catch { res.status(400).json({ error: 'BAD_BACKUP' }); }
});
app.get('/api/backup/list', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const files = fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.json')).sort().reverse()
    .map((f) => ({ name: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size }));
  res.json(files);
});
app.get('/api/backup/file/:name', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const f = path.basename(req.params.name);
  const full = path.join(BACKUP_DIR, f);
  if (!f.endsWith('.json') || !fs.existsSync(full)) return res.status(404).json({ error: 'NOT_FOUND' });
  res.download(full);
});
/* OPTIONAL Google Drive auto-upload hook.
   To enable: create a Google Cloud project, enable Drive API, create an OAuth
   client, and set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REFRESH_TOKEN
   env vars. Then implement the resumable upload of the latest backup file here
   (see Google Drive API v3 files.create with multipart upload). Until then this
   endpoint stays a stub and the app works fully without it. */
app.post('/api/backup/drive', auth, needAdmin, (req, res) => {
  res.status(501).json({ ok: false, code: 'DRIVE_NOT_CONFIGURED',
    message: 'Google Drive upload is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN env vars and implement the upload in server.js (see code comments).' });
});

/* ---------- static frontend ---------- */
const DIST = path.join(__dirname, '..', 'client', 'dist');
if (fs.existsSync(DIST)) {
  app.use(express.static(DIST));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return res.status(404).json({ error: 'NOT_FOUND' });
    res.sendFile(path.join(DIST, 'index.html'));
  });
} else {
  app.get('/', (req, res) => res.json({ ok: true, app: 'kashf', api: '/api', note: 'frontend not built yet — run npm run build in client/' }));
}
app.use('/api', (req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

/* ---------- boot ---------- */
seedIfNeeded();
const bkp = autoBackup();
// BASE_PATH lets the app live under a sub-path like /kashf on Alwaysdata
// (e.g. site address kashf.alwaysdata.net/kashf). The whole app — API and
// frontend — is mounted under it; the frontend build uses relative asset
// paths (vite base './') and prefixes /api calls with VITE_BASE_PATH.
const BASE_PATH = (process.env.BASE_PATH || '').replace(/\/+$/, '');
const handler = BASE_PATH
  ? (() => { const m = express(); m.use(BASE_PATH, app); return m; })()
  : app;
handler.listen(PORT, () => console.log(`Kashf server on :${PORT}${BASE_PATH ? ' base ' + BASE_PATH : ''}${bkp ? ' (backup: ' + bkp + ')' : ''}`));
