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

/* ---------- wallet accounts ---------- */
// Balance = opening_balance + inflows − outflows (computed on the fly, never stored).
// Inflows:  sales.paid (by account_id), ledger_payments direction='in' (by account_id).
// Outflows: purchases.paid (by account_id), expenses.amount incl. personal (by account_id),
//           ledger_payments direction='out' (by account_id).
function getAccount(id) {
  if (!id) return null;
  return db.prepare('SELECT * FROM accounts WHERE id=? AND disabled=0').get(Number(id)) || null;
}
function accountStats(id) {
  const a = db.prepare('SELECT * FROM accounts WHERE id=?').get(id);
  if (!a) return null;
  const opening = r2(a.opening_balance || 0);
  const inflow = r2(
    sum('SELECT SUM(paid) v FROM sales WHERE account_id=?', id) +
    sum("SELECT SUM(amount) v FROM ledger_payments WHERE account_id=? AND direction='in'", id));
  const outflow = r2(
    sum('SELECT SUM(paid) v FROM purchases WHERE account_id=?', id) +
    sum('SELECT SUM(amount) v FROM expenses WHERE account_id=?', id) +
    sum("SELECT SUM(amount) v FROM ledger_payments WHERE account_id=? AND direction='out'", id));
  return { id: a.id, name_ur: a.name_ur, name_en: a.name_en, type: a.type, disabled: a.disabled, opening, inflow, outflow, balance: r2(opening + inflow - outflow) };
}
// Voucher numbers are derived from the row id (PV-0001 …), so they stay unique
// even if rows are deleted. Existing rows without one are backfilled at boot.
function nextVoucherNo() {
  const n = db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM ledger_payments').get().n;
  return 'PV-' + String(n).padStart(4, '0');
}
function backfillVoucherNos() {
  db.prepare(`UPDATE ledger_payments SET voucher_no='PV-'||substr('0000'||id,-4) WHERE voucher_no IS NULL OR voucher_no=''`).run();
}

/* ---------- auth ---------- */
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!tok) return res.status(401).json({ error: 'NO_TOKEN' });
  try {
    const p = jwt.verify(tok, JWT_SECRET);
    const u = db.prepare('SELECT id,name,username,role,shop_id,disabled,is_super FROM users WHERE id=?').get(p.id);
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
  res.json({ token, user: { id: u.id, name: u.name, username: u.username, role: u.role, shop_id: u.shop_id, is_super: u.is_super || 0 } });
});
app.get('/api/auth/me', auth, (req, res) => res.json(req.user));

/* ---------- users (admin) ---------- */
app.get('/api/users', auth, needAdmin, (req, res) => {
  res.json(db.prepare('SELECT id,name,username,role,shop_id,disabled,is_super,created_at FROM users ORDER BY id').all());
});
app.post('/api/users', auth, needAdmin, (req, res) => {
  const { name, username, password, role, shop_id } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'MISSING_FIELDS' });
  if (!['admin', 'staff', 'shop'].includes(role)) return res.status(400).json({ error: 'BAD_ROLE' });
  // Only the main (super) admin can create admin users
  if (role === 'admin' && !req.user.is_super) return res.status(403).json({ error: 'SUPER_ONLY' });
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
  // Main (super) admin is protected: nobody else may touch this account
  if (u.is_super && id !== req.user.id) return res.status(403).json({ error: 'SUPER_PROTECTED' });
  // Fellow admins are managed by the super admin only (edit/password/disable)
  if (u.role === 'admin' && id !== req.user.id && !req.user.is_super)
    return res.status(403).json({ error: 'ADMINS_BY_SUPER_ONLY' });
  // Granting/removing the admin role is a super-admin power
  if (role && role !== u.role && (role === 'admin' || u.role === 'admin') && !req.user.is_super)
    return res.status(403).json({ error: 'SUPER_ONLY' });
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
  // The main (super) admin can never be deleted
  if (u.is_super) return res.status(403).json({ error: 'SUPER_PROTECTED' });
  // Only the super admin can delete fellow admins
  if (u.role === 'admin' && !req.user.is_super) return res.status(403).json({ error: 'ADMINS_BY_SUPER_ONLY' });
  if (u.role === 'admin') {
    const c = db.prepare("SELECT COUNT(*) v FROM users WHERE role='admin' AND id<>?").get(id).v;
    if (!c) return res.status(400).json({ error: 'LAST_ADMIN' });
  }
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  res.json({ ok: true });
});

/* ---------- shops / suppliers ---------- */
function crud(base, table, fields, { shopScoped = false, enrich = null } = {}) {
  app.get(base, auth, (req, res) => {
    const withBal = (rows) => (enrich ? rows.map(enrich) : rows);
    if (req.user.role === 'shop') {
      if (!shopScoped) return res.status(403).json({ error: 'FORBIDDEN' });
      const r = db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(req.user.shop_id);
      return res.json(withBal(r ? [r] : []));
    }
    res.json(withBal(db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()));
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
crud('/api/shops', 'shops', ['name', 'phone', 'address', 'whatsapp', 'opening_balance', 'disabled'], {
  shopScoped: true,
  // Current balance: +ve = shop owes us (matches ledger closing)
  enrich: (s) => ({ ...s, balance: r2((s.opening_balance || 0)
    + sum(`SELECT SUM(total-paid) v FROM sales WHERE customer_type='shop' AND shop_id=?`, s.id)
    - sum(`SELECT SUM(amount) v FROM ledger_payments WHERE party_type='shop' AND party_id=? AND direction='in'`, s.id)) }),
});
crud('/api/suppliers', 'suppliers', ['name', 'phone', 'address', 'opening_balance'], {
  // Current balance: +ve = we owe the supplier (matches ledger closing)
  enrich: (s) => ({ ...s, balance: r2((s.opening_balance || 0)
    + sum(`SELECT SUM(total-paid) v FROM purchases WHERE supplier_id=?`, s.id)
    - sum(`SELECT SUM(amount) v FROM ledger_payments WHERE party_type='supplier' AND party_id=? AND direction='out'`, s.id)) }),
});

/* ---------- wallet accounts (بٹوہ) ---------- */
const ACCT_TYPES = ['cash', 'easypaisa', 'jazzcash', 'bank', 'other'];
const noShop = (req, res, next) =>
  req.user.role === 'shop' ? res.status(403).json({ error: 'FORBIDDEN' }) : next();
app.get('/api/accounts', auth, noShop, (req, res) => {
  const rows = db.prepare('SELECT id FROM accounts ORDER BY id').all();
  res.json(rows.map((r) => accountStats(r.id)));
});
app.post('/api/accounts', auth, needAdmin, (req, res) => {
  const { name_ur, name_en = '', type = 'other', opening_balance = 0 } = req.body || {};
  if (!name_ur || !ACCT_TYPES.includes(type)) return res.status(400).json({ error: 'BAD_ACCOUNT' });
  const r = db.prepare(`INSERT INTO accounts (name_ur,name_en,type,opening_balance,created_at) VALUES (?,?,?,?,?)`)
    .run(name_ur, name_en, type, Number(opening_balance) || 0, nowISO());
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/accounts/:id', auth, needAdmin, (req, res) => {
  const a = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'NOT_FOUND' });
  const { name_ur, name_en, type, opening_balance, disabled } = req.body || {};
  if (type !== undefined && !ACCT_TYPES.includes(type)) return res.status(400).json({ error: 'BAD_TYPE' });
  db.prepare(`UPDATE accounts SET name_ur=COALESCE(?,name_ur), name_en=COALESCE(?,name_en),
    type=COALESCE(?,type), opening_balance=COALESCE(?,opening_balance),
    disabled=COALESCE(?,disabled) WHERE id=?`)
    .run(name_ur ?? null, name_en ?? null, type ?? null,
      opening_balance === undefined ? null : Number(opening_balance) || 0,
      disabled === undefined ? null : (disabled ? 1 : 0), req.params.id);
  res.json({ ok: true });
});
app.get('/api/accounts/:id/statement', auth, noShop, (req, res) => {
  const a = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'NOT_FOUND' });
  const { from = '2000-01-01', to = '2999-12-31' } = req.query;
  const id = a.id;
  const evts = [];
  for (const s of db.prepare(`SELECT date,bill_no,paid,customer_type,shop_id,
      (SELECT name FROM shops WHERE id=s.shop_id) shop_name
      FROM sales s WHERE account_id=? AND paid>0 ORDER BY date,id`).all(id))
    evts.push({ date: s.date, ref: `بل ${s.bill_no}`, desc: s.customer_type === 'shop' ? (s.shop_name || '') : 'چلتا گاہک', rin: s.paid, rout: 0 });
  for (const p of db.prepare(`SELECT date,amount,voucher_no,party_type,party_id,note FROM ledger_payments
      WHERE account_id=? AND direction='in' ORDER BY date,id`).all(id))
    evts.push({ date: p.date, ref: `واؤچر ${p.voucher_no || ''}`, desc: `${partyName(p.party_type, p.party_id)} — وصولی${p.note ? ' — ' + p.note : ''}`, rin: p.amount, rout: 0 });
  for (const p of db.prepare(`SELECT date,bill_no,paid,supplier_id,
      (SELECT name FROM suppliers WHERE id=p.supplier_id) sup_name
      FROM purchases p WHERE account_id=? AND paid>0 ORDER BY date,id`).all(id))
    evts.push({ date: p.date, ref: `خرید ${p.bill_no}`, desc: p.sup_name || '', rin: 0, rout: p.paid });
  for (const e of db.prepare(`SELECT date,category,amount,note FROM expenses WHERE account_id=? ORDER BY date,id`).all(id))
    evts.push({ date: e.date, ref: e.category, desc: e.note || '', rin: 0, rout: e.amount });
  for (const p of db.prepare(`SELECT date,amount,voucher_no,party_type,party_id,note FROM ledger_payments
      WHERE account_id=? AND direction='out' ORDER BY date,id`).all(id))
    evts.push({ date: p.date, ref: `واؤچر ${p.voucher_no || ''}`, desc: `${partyName(p.party_type, p.party_id)} — ادائیگی${p.note ? ' — ' + p.note : ''}`, rin: 0, rout: p.amount });
  evts.sort((x, y) => x.date < y.date ? -1 : x.date > y.date ? 1 : 0);
  const opening = r2(a.opening_balance || 0);
  // Running balance starts from opening + net of pre-period events
  let pre = opening;
  for (const e of evts) if (e.date < from) pre = r2(pre + (e.rin || 0) - (e.rout || 0));
  const out = [{ date: '', ref: 'ابتدائی بیلنس', desc: '', rin: 0, rout: 0, balance: pre }];
  let b2 = pre;
  for (const e of evts) {
    if (e.date < from || e.date > to) continue;
    b2 = r2(b2 + (e.rin || 0) - (e.rout || 0));
    out.push({ ...e, balance: b2 });
  }
  res.json({ account: accountStats(id), from, to, rows: out, closing: out.length ? out[out.length - 1].balance : pre });
});
function partyName(pt, pid) {
  if (pt === 'shop') return db.prepare('SELECT name FROM shops WHERE id=?').get(pid)?.name || `#${pid}`;
  return db.prepare('SELECT name FROM suppliers WHERE id=?').get(pid)?.name || `#${pid}`;
}

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
  let sql = `SELECT p.*, s.name supplier_name,
             COALESCE((SELECT SUM(qty) FROM purchase_items pi WHERE pi.purchase_id=p.id), 0) total_qty
             FROM purchases p LEFT JOIN suppliers s ON s.id=p.supplier_id
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
  const { supplier_id, date, bill_no, items, bilty_amt = 0, bilty_paid_by = 'supplier', paid = 0, note = '', account_id = null } = body;
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
  const paidN = Number(paid) || 0;
  let acctId = null;
  if (paidN > 0) {
    const a = getAccount(account_id);
    if (!a) throw { status: 400, code: 'BAD_ACCOUNT' };
    acctId = a.id;
  } else if (account_id != null && account_id !== '') throw { status: 400, code: 'ACCOUNT_NOT_ALLOWED' };
  const id = db.prepare(`INSERT INTO purchases
    (supplier_id,date,bill_no,subtotal,bilty_amt,bilty_paid_by,total,paid,balance,account_id,note,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(supplier_id, date, bill_no || nextPurchaseBill(), subtotal, Number(bilty_amt) || 0,
      bilty_paid_by, total, paidN, balance, acctId, note, createdBy, nowISO()).lastInsertRowid;
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
  const ps = db.prepare('UPDATE products SET stock = stock - ? WHERE id=?');
  for (const it of items) {
    const pr = db.prepare('SELECT stock FROM products WHERE id=?').get(it.product_id);
    // Clamp at 0 instead of blocking: service/charge items (e.g. bilty) have no
    // physical stock, so deducting would go negative. Real goods still deduct
    // correctly when stock is available.
    const deduct = Math.min(it.qty, Math.max(0, pr ? pr.stock : 0));
    if (deduct > 0) ps.run(deduct, it.product_id);
  }
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
  const s = db.prepare(`SELECT s.*, sh.name shop_name, a.name_ur account_name FROM sales s
    LEFT JOIN shops sh ON sh.id=s.shop_id LEFT JOIN accounts a ON a.id=s.account_id WHERE s.id=?`).get(req.params.id);
  if (!s) return res.status(404).json({ error: 'NOT_FOUND' });
  if (req.user.role === 'shop' && s.shop_id !== req.user.shop_id) return res.status(403).json({ error: 'FORBIDDEN' });
  s.items = db.prepare(`SELECT si.*, pr.name_ur, pr.unit, pr.purchase_rate FROM sale_items si JOIN products pr ON pr.id=si.product_id WHERE si.sale_id=?`).all(s.id);
  s.expenses = db.prepare(`SELECT id, date, category, amount, note FROM expenses WHERE sale_id=? ORDER BY id`).all(s.id);
  res.json(s);
});
function applySale(body, createdBy, billNo) {
  const { date, customer_type = 'walkin', shop_id = null, items, discount = 0,
    paid = 0, note = '', manual_expenses = [],
    account_id = null, expense_account_id = null } = body;
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
  const paidN = Number(paid) || 0;
  // Wallet rule: money actually received must land in a real account.
  // paid>0 => account_id required & valid; paid=0 (credit) => account_id must be NULL.
  let acctId = null;
  if (paidN > 0) {
    const a = getAccount(account_id);
    if (!a) throw { status: 400, code: 'BAD_ACCOUNT' };
    acctId = a.id;
  } else if (account_id != null && account_id !== '') throw { status: 400, code: 'ACCOUNT_NOT_ALLOWED' };
  const method = paidN > 0 ? (getAccount(acctId)?.type || 'cash') : 'credit';
  const subtotal = r2(items.reduce((a, i) => a + i.qty * i.rate, 0));
  // Owner rule (2026-10-08): bilty / petrol / other delivery expenses are OUR cost.
  // They are NEVER added to the customer bill. Staff adds them manually as
  // separate business expense entries linked to the bill, so the ledger shows
  // each one as its own clear line.
  const total = r2(subtotal - (Number(discount) || 0));
  const balance = r2(total - (Number(paid) || 0));
  const finalBillNo = billNo || nextSaleBill();
  const id = db.prepare(`INSERT INTO sales
    (bill_no,date,customer_type,shop_id,subtotal,bilty_amt,discount,expense_petrol,total,paid,balance,payment_method,account_id,note,created_by,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(finalBillNo, date, customer_type, customer_type === 'shop' ? shop_id : null,
      subtotal, 0, Number(discount) || 0, 0,
      total, paidN, balance, method, acctId, note, createdBy, nowISO()).lastInsertRowid;
  const si = db.prepare('INSERT INTO sale_items (sale_id,product_id,qty,rate,amount) VALUES (?,?,?,?,?)');
  const ps = db.prepare('UPDATE products SET stock = stock - ? WHERE id=?');
  for (const it of items) { si.run(id, it.product_id, it.qty, it.rate, r2(it.qty * it.rate)); ps.run(it.qty, it.product_id); }
  // Manual expenses -> separate business expense entries linked to this bill
  if (Array.isArray(manual_expenses) && manual_expenses.length) {
    const ea = getAccount(expense_account_id);
    if (!ea) throw { status: 400, code: 'BAD_EXPENSE_ACCOUNT' };
    const ins = db.prepare(`INSERT INTO expenses (date,category,amount,note,kind,sale_id,account_id,created_by)
      VALUES (?,?,?,?,?,?,?,?)`);
    for (const e of manual_expenses) {
      const amt = Number(e.amount) || 0;
      const cat = String(e.category || '').trim();
      if (!(amt > 0) || !cat) throw { status: 400, code: 'BAD_MANUAL_EXPENSE' };
      const enote = [`بل نمبر ${finalBillNo}`, String(e.note || '').trim()].filter(Boolean).join(' — ');
      ins.run(date, cat, r2(amt), enote, 'business', id, ea.id, createdBy);
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

/* ---------- payments / vouchers ---------- */
// direction: legacy stored values are 'in' (money received INTO an account,
// e.g. shop paid us) / 'out' (money paid OUT of an account, e.g. we paid a
// supplier). The API accepts 'received'/'paid' from clients and maps them.
const DIRMAP = { received: 'in', paid: 'out', in: 'in', out: 'out' };
app.get('/api/payments', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { from = '2000-01-01', to = '2999-12-31', party_type, party_id } = req.query;
  let sql = `SELECT lp.*, a.name_ur account_name,
    COALESCE((SELECT name FROM shops WHERE id=lp.party_id AND lp.party_type='shop'),
             (SELECT name FROM suppliers WHERE id=lp.party_id AND lp.party_type='supplier')) party_name
    FROM ledger_payments lp LEFT JOIN accounts a ON a.id=lp.account_id
    WHERE lp.date BETWEEN ? AND ?`; const a = [from, to];
  if (party_type) { sql += ' AND lp.party_type=?'; a.push(party_type); }
  if (party_id) { sql += ' AND lp.party_id=?'; a.push(party_id); }
  res.json(db.prepare(sql + ' ORDER BY lp.date DESC, lp.id DESC').all(...a));
});
app.get('/api/payments/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const p = db.prepare(`SELECT lp.*, a.name_ur account_name, a.name_en account_en FROM ledger_payments lp
    LEFT JOIN accounts a ON a.id=lp.account_id WHERE lp.id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'NOT_FOUND' });
  p.party_name = partyName(p.party_type, p.party_id);
  res.json(p);
});
app.post('/api/payments', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const { date, party_type, party_id, amount, account_id, direction, note = '' } = req.body || {};
  const dir = DIRMAP[direction];
  if (!date || !['shop', 'supplier'].includes(party_type) || !party_id || !(amount > 0) || !dir)
    return res.status(400).json({ error: 'BAD_PAYMENT' });
  const party = party_type === 'shop'
    ? db.prepare('SELECT id FROM shops WHERE id=?').get(party_id)
    : db.prepare('SELECT id FROM suppliers WHERE id=?').get(party_id);
  if (!party) return res.status(400).json({ error: 'BAD_PARTY' });
  const a = getAccount(account_id);
  if (!a) return res.status(400).json({ error: 'BAD_ACCOUNT' });
  const voucher_no = nextVoucherNo();
  const r = db.prepare(`INSERT INTO ledger_payments (date,party_type,party_id,amount,method,direction,note,account_id,voucher_no,created_by)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(date, party_type, party_id, amount, a.type, dir, note, a.id, voucher_no, req.user.id);
  res.json({ id: r.lastInsertRowid, voucher_no });
});
app.put('/api/payments/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const f = ['date', 'amount', 'direction', 'note'].filter((k) => req.body[k] !== undefined);
  const vals = f.map((k) => k === 'direction' ? DIRMAP[req.body[k]] : req.body[k]);
  if (f.includes('direction') && !DIRMAP[req.body.direction]) return res.status(400).json({ error: 'BAD_DIRECTION' });
  if (req.body.account_id !== undefined) {
    const a = getAccount(req.body.account_id);
    if (!a) return res.status(400).json({ error: 'BAD_ACCOUNT' });
    f.push('account_id', 'method'); vals.push(a.id, a.type);
  }
  if (f.length) db.prepare(`UPDATE ledger_payments SET ${f.map((k) => `${k}=?`).join(',')} WHERE id=?`)
    .run(...vals, req.params.id);
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
  const { date, category, amount, note = '', kind = 'business', account_id = null } = req.body || {};
  if (!date || !category || !(amount > 0) || !['business', 'personal'].includes(kind))
    return res.status(400).json({ error: 'BAD_EXPENSE' });
  const a = getAccount(account_id);
  if (!a) return res.status(400).json({ error: 'BAD_ACCOUNT' });
  const r = db.prepare('INSERT INTO expenses (date,category,amount,note,kind,account_id,created_by) VALUES (?,?,?,?,?,?,?)')
    .run(date, category, amount, note, kind, a.id, req.user.id);
  res.json({ id: r.lastInsertRowid });
});
app.put('/api/expenses/:id', auth, (req, res) => {
  if (req.user.role === 'shop') return res.status(403).json({ error: 'FORBIDDEN' });
  const f = ['date', 'category', 'amount', 'note', 'kind'].filter((k) => req.body[k] !== undefined);
  if (req.body.account_id !== undefined) {
    const a = getAccount(req.body.account_id);
    if (!a) return res.status(400).json({ error: 'BAD_ACCOUNT' });
    f.push('account_id');
  }
  if (f.length) db.prepare(`UPDATE expenses SET ${f.map((k) => `${k}=?`).join(',')} WHERE id=?`)
    .run(...f.map((k) => k === 'account_id' ? getAccount(req.body.account_id).id : req.body[k]), req.params.id);
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
      - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='shop' AND party_id=? AND direction='in'", sid)
      + sum('SELECT opening_balance v FROM shops WHERE id=?', sid));
    const recent = db.prepare(`SELECT id,bill_no,date,total,paid,balance FROM sales
      WHERE shop_id=? ORDER BY date DESC, id DESC LIMIT 10`).all(sid);
    return res.json({ shop: true, balance: bal, recent });
  }
  const mStart = T.slice(0, 7) + '-01';
  const receivables = r2(sum("SELECT SUM(total-paid) v FROM sales WHERE customer_type='shop'")
    - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='shop' AND direction='in'")
    + sum('SELECT SUM(opening_balance) v FROM shops WHERE disabled=0'));
  const payables = r2(sum('SELECT SUM(total-paid) v FROM purchases')
    - sum("SELECT SUM(amount) v FROM ledger_payments WHERE party_type='supplier' AND direction='out'")
    + sum('SELECT SUM(opening_balance) v FROM suppliers'));
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
  const wallets = db.prepare('SELECT id FROM accounts WHERE disabled=0 ORDER BY id').all().map((r) => accountStats(r.id));
  const walletTotal = r2(wallets.reduce((s, w) => s + (w?.balance || 0), 0));
  res.json({
    todaySales: r2(sum('SELECT SUM(total) v FROM sales WHERE date=?', T)),
    weeklySales: r2(sum('SELECT SUM(total) v FROM sales WHERE date BETWEEN ? AND ?', addDays(T, -6), T)),
    monthlyTurnover: r2(sum('SELECT SUM(total) v FROM sales WHERE date BETWEEN ? AND ?', mStart, T)),
    receivables, payables, lowStock,
    netProfit: mp.netProfit, savings: mp.savings,
    weekly: wk,
    wallets, walletTotal,
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
  const partyRow = party_type === 'shop'
    ? db.prepare('SELECT opening_balance FROM shops WHERE id=?').get(party_id)
    : db.prepare('SELECT opening_balance FROM suppliers WHERE id=?').get(party_id);
  const partyOpening = r2(partyRow?.opening_balance || 0);
  // Convention: shops +ve = they owe us (receivable); suppliers +ve = we owe them (payable).
  if (party_type === 'shop') {
    for (const s of db.prepare(`SELECT s.date,s.bill_no,s.total,s.paid,a.name_ur account_name
        FROM sales s LEFT JOIN accounts a ON a.id=s.account_id
        WHERE s.customer_type='shop' AND s.shop_id=? ORDER BY s.date,s.id`).all(party_id)) {
      evts.push({ date: s.date, desc: `بل ${s.bill_no}`, debit: s.total, credit: 0 });
      // Money paid at bill time reduces what the shop owes — show it as a receipt
      // so the ledger closing matches the dashboard receivables (total-paid).
      if ((s.paid || 0) > 0) evts.push({ date: s.date, desc: `وصولی (بل کے وقت${s.account_name ? ' — ' + s.account_name : ''})`, debit: 0, credit: s.paid });
    }
    for (const p of db.prepare(`SELECT date,amount,method,note,voucher_no FROM ledger_payments WHERE party_type='shop' AND party_id=? AND direction='in' ORDER BY date,id`).all(party_id))
      evts.push({ date: p.date, desc: `وصولی${p.voucher_no ? ' ' + p.voucher_no : ''} (${p.method})${p.note ? ' — ' + p.note : ''}`, debit: 0, credit: p.amount });
  } else {
    for (const p of db.prepare(`SELECT p.date,p.bill_no,p.total,p.paid,a.name_ur account_name
        FROM purchases p LEFT JOIN accounts a ON a.id=p.account_id
        WHERE p.supplier_id=? ORDER BY p.date,p.id`).all(party_id)) {
      evts.push({ date: p.date, desc: `خرید ${p.bill_no}`, debit: 0, credit: p.total });
      // Money paid at purchase time reduces what we owe — show it as a payment
      // so the ledger closing matches the dashboard payables (total-paid).
      if ((p.paid || 0) > 0) evts.push({ date: p.date, desc: `ادائیگی (خرید کے وقت${p.account_name ? ' — ' + p.account_name : ''})`, debit: p.paid, credit: 0 });
    }
    for (const p of db.prepare(`SELECT date,amount,method,note,voucher_no FROM ledger_payments WHERE party_type='supplier' AND party_id=? AND direction='out' ORDER BY date,id`).all(party_id))
      evts.push({ date: p.date, desc: `ادائیگی${p.voucher_no ? ' ' + p.voucher_no : ''} (${p.method})${p.note ? ' — ' + p.note : ''}`, debit: p.amount, credit: 0 });
  }
  // Period-start balance = party opening + net of pre-period events
  // (sales and payment events are each date-ordered but need a combined sort
  // for a correct running balance; stable sort keeps bill before its payment)
  evts.sort((a, b) => a.date < b.date ? -1 : a.date > b.date ? 1 : 0);
  let opening = partyOpening;
  for (const e of evts) {
    if (e.date >= from || e.date === '') continue;
    opening = r2(party_type === 'shop' ? opening + e.debit - e.credit : opening + e.credit - e.debit);
  }
  const rows = [{ date: '', desc: 'ابتدائی بقایا / Opening',
    debit: party_type === 'shop' ? opening : 0, credit: party_type === 'supplier' ? opening : 0, balance: opening }];
  let bal = opening;
  for (const e of evts) {
    if (e.date < from) continue;
    bal = r2(party_type === 'shop' ? bal + e.debit - e.credit : bal + e.credit - e.debit);
    if (e.date <= to) rows.push({ ...e, balance: bal });
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
    WHERE s.paid > 0 AND s.date BETWEEN ? AND ?
    ORDER BY s.date DESC, s.id DESC`).all(from, to);
  const qq = q.trim();
  res.json(qq ? rows.filter((r) => (r.bill_no + r.items + r.shop_name).includes(qq)) : rows);
});

/* ---------- stock report: purchased vs sold vs available ---------- */
app.get('/api/reports/stock', auth, noShop, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.name_ur, p.name_en, p.unit, p.stock, p.low_threshold,
      COALESCE((SELECT SUM(qty) FROM purchase_items pi WHERE pi.product_id = p.id), 0) AS purchased,
      COALESCE((SELECT SUM(qty) FROM sale_items si WHERE si.product_id = p.id), 0) AS sold
    FROM products p WHERE p.disabled = 0 ORDER BY p.name_ur`).all();
  res.json(rows);
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

/* ---------- admin: wipe all transactional data ---------- */
// Scope: deletes ALL transactions (sales, sale_items, purchases, purchase_items,
// ledger_payments, expenses), resets product stock to 0 and party opening
// balances to 0. Keeps masters: users, products, shops, suppliers, accounts.
// A full JSON backup is written first; the client must send {confirm:'DELETE'}.
app.post('/api/admin/wipe', auth, needAdmin, (req, res) => {
  if (!req.body || req.body.confirm !== 'DELETE') return res.status(400).json({ error: 'CONFIRM_REQUIRED' });
  const stamp = `kashf-backup-prewipe-${todayLocal()}-${Date.now()}.json`;
  try {
    fs.writeFileSync(path.join(BACKUP_DIR, stamp), JSON.stringify(exportAll(), null, 1));
  } catch (e) { return res.status(500).json({ error: 'BACKUP_FAILED' }); }
  db.exec('BEGIN');
  try {
    for (const t of ['sale_items', 'sales', 'purchase_items', 'purchases', 'ledger_payments', 'expenses'])
      db.prepare(`DELETE FROM ${t}`).run();
    db.prepare('UPDATE products SET stock=0').run();
    db.prepare('UPDATE shops SET opening_balance=0').run();
    db.prepare('UPDATE suppliers SET opening_balance=0').run();
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); return res.status(500).json({ error: 'WIPE_FAILED' }); }
  res.json({ ok: true, backup: stamp });
});

/* ---------- static frontend ---------- */
const DIST = path.join(__dirname, '..', 'client', 'dist');
if (fs.existsSync(DIST)) {
  // Never HTTP-cache the service worker / manifest: the browser must re-check
  // for a new SW on every visit, otherwise PWA updates never reach phones.
  app.get(['/sw.js', '/manifest.json'], (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
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
backfillVoucherNos();
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
