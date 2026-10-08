/* Kashf DB layer — node:sqlite (built-in, no native deps) */
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'kashf.db'));
db.exec('PRAGMA journal_mode = WAL;');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, username TEXT NOT NULL UNIQUE, pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff', shop_id INTEGER NULL,
  disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, phone TEXT DEFAULT '', address TEXT DEFAULT '',
  whatsapp TEXT DEFAULT '', disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS suppliers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, phone TEXT DEFAULT '', address TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_ur TEXT NOT NULL, name_en TEXT DEFAULT '', sku TEXT DEFAULT '',
  barcode TEXT DEFAULT '', category TEXT DEFAULT '', unit TEXT DEFAULT 'کلو',
  purchase_rate REAL NOT NULL DEFAULT 0, sale_rate REAL NOT NULL DEFAULT 0,
  wholesale_rate REAL NOT NULL DEFAULT 0, stock REAL NOT NULL DEFAULT 0,
  low_threshold REAL NOT NULL DEFAULT 5, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT, supplier_id INTEGER NOT NULL,
  date TEXT NOT NULL, bill_no TEXT DEFAULT '', subtotal REAL NOT NULL DEFAULT 0,
  bilty_amt REAL NOT NULL DEFAULT 0, bilty_paid_by TEXT NOT NULL DEFAULT 'supplier',
  total REAL NOT NULL DEFAULT 0, paid REAL NOT NULL DEFAULT 0, balance REAL NOT NULL DEFAULT 0,
  note TEXT DEFAULT '', created_by INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS purchase_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, purchase_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL, qty REAL NOT NULL, rate REAL NOT NULL, amount REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT, bill_no TEXT NOT NULL UNIQUE,
  date TEXT NOT NULL, customer_type TEXT NOT NULL DEFAULT 'walkin', shop_id INTEGER NULL,
  subtotal REAL NOT NULL DEFAULT 0, bilty_amt REAL NOT NULL DEFAULT 0,
  discount REAL NOT NULL DEFAULT 0, expense_petrol REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0, paid REAL NOT NULL DEFAULT 0, balance REAL NOT NULL DEFAULT 0,
  payment_method TEXT NOT NULL DEFAULT 'cash', note TEXT DEFAULT '',
  created_by INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sale_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sale_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL, qty REAL NOT NULL, rate REAL NOT NULL, amount REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL,
  party_type TEXT NOT NULL, party_id INTEGER NOT NULL,
  amount REAL NOT NULL, method TEXT DEFAULT 'cash',
  direction TEXT NOT NULL, note TEXT DEFAULT '', created_by INTEGER
);
CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT NOT NULL,
  category TEXT NOT NULL, amount REAL NOT NULL, note TEXT DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'business', created_by INTEGER
);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name_ur TEXT NOT NULL, name_en TEXT DEFAULT '',
  type TEXT NOT NULL DEFAULT 'other',
  opening_balance REAL NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
`;
db.exec(SCHEMA);
// Lightweight migrations for existing databases
for (const sql of [
  'ALTER TABLE expenses ADD COLUMN sale_id INTEGER',
  'ALTER TABLE sales ADD COLUMN account_id INTEGER',
  'ALTER TABLE purchases ADD COLUMN account_id INTEGER',
  'ALTER TABLE expenses ADD COLUMN account_id INTEGER',
  'ALTER TABLE ledger_payments ADD COLUMN account_id INTEGER',
  'ALTER TABLE ledger_payments ADD COLUMN voucher_no TEXT',
  'ALTER TABLE shops ADD COLUMN opening_balance REAL DEFAULT 0',
  'ALTER TABLE suppliers ADD COLUMN opening_balance REAL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN is_super INTEGER NOT NULL DEFAULT 0',
]) {
  try { db.exec(sql); } catch (e) { /* column already exists */ }
}
// Main (super) admin protection: exactly one protected super admin must exist.
// Fresh DBs get it from seedIfNeeded; existing DBs promote the oldest admin once.
try {
  const n = db.prepare('SELECT COUNT(*) c FROM users WHERE is_super=1').get().c;
  if (!n) {
    const adm = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
    if (adm) db.prepare('UPDATE users SET is_super=1 WHERE id=?').run(adm.id);
  }
} catch (e) { /* users table not seeded yet */ }

/* ---------- wallet accounts ---------- */
// Sign conventions (kept consistent across server.js):
// - shops: balance +ve = THEY OWE US (receivable). Credit sale increases it;
//   payment received ('in') decreases it. shops.opening_balance +5000 => they owe us 5000.
// - suppliers: balance +ve = WE OWE THEM (payable). Credit purchase increases it;
//   payment made ('out') decreases it. suppliers.opening_balance +5000 => we owe them 5000.
// - accounts (wallets): balance = opening_balance + inflows - outflows (computed, never stored).
//   Inflows:  sales.paid (by account_id), ledger_payments direction='in' (by account_id).
//   Outflows: purchases.paid (by account_id), expenses.amount incl. personal (by account_id),
//             ledger_payments direction='out' (by account_id).
// - ledger_payments.direction uses the legacy values 'in' (money received into an
//   account) / 'out' (money paid out of an account). The voucher API accepts
//   'received'/'paid' from the client and maps them to 'in'/'out'.
function seedAccountsIfNeeded() {
  const n = db.prepare('SELECT COUNT(*) c FROM accounts').get().c;
  if (n > 0) return false;
  const iso = nowISO();
  const ins = db.prepare(`INSERT INTO accounts (name_ur,name_en,type,opening_balance,created_at) VALUES (?,?,?,?,?)`);
  ins.run('نقد رقم', 'Cash', 'cash', 0, iso);
  ins.run('EasyPaisa', 'EasyPaisa', 'easypaisa', 0, iso);
  ins.run('JazzCash', 'JazzCash', 'jazzcash', 0, iso);
  ins.run('بینک', 'Bank', 'bank', 0, iso);
  return true;
}
// One-time mapping of legacy payment_method/method strings to accounts (only rows
// whose account_id is still NULL, so it never overwrites user choices).
function mapLegacyAccounts() {
  const idOf = (type) => db.prepare('SELECT id FROM accounts WHERE type=? AND disabled=0').get(type)?.id || null;
  const cash = idOf('cash'), ep = idOf('easypaisa'), bank = idOf('bank');
  if (cash) {
    db.prepare(`UPDATE sales SET account_id=? WHERE account_id IS NULL AND payment_method='cash' AND paid>0`).run(cash);
    db.prepare(`UPDATE ledger_payments SET account_id=? WHERE account_id IS NULL AND method='cash'`).run(cash);
  }
  if (ep) {
    db.prepare(`UPDATE sales SET account_id=? WHERE account_id IS NULL AND payment_method IN ('wallet','easypaisa') AND paid>0`).run(ep);
    db.prepare(`UPDATE ledger_payments SET account_id=? WHERE account_id IS NULL AND method IN ('wallet','easypaisa')`).run(ep);
  }
  if (bank) {
    db.prepare(`UPDATE sales SET account_id=? WHERE account_id IS NULL AND payment_method='bank' AND paid>0`).run(bank);
    db.prepare(`UPDATE ledger_payments SET account_id=? WHERE account_id IS NULL AND method='bank'`).run(bank);
  }
}
seedAccountsIfNeeded();
mapLegacyAccounts();

function todayLocal(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function nowISO() { return new Date().toISOString(); }
const r2 = (n) => Math.round((Number(n) || 0) * 100) / 100;

const TABLES = ['users', 'shops', 'suppliers', 'products', 'purchases', 'purchase_items',
  'sales', 'sale_items', 'ledger_payments', 'expenses', 'accounts'];

function exportAll() {
  const out = { app: 'kashf', exported_at: nowISO(), tables: {} };
  for (const t of TABLES) out.tables[t] = db.prepare(`SELECT * FROM ${t}`).all();
  return out;
}

function importAll(data) {
  if (!data || !data.tables) throw new Error('BAD_BACKUP');
  db.exec('BEGIN');
  try {
    for (const t of TABLES) {
      const rows = data.tables[t] || [];
      db.prepare(`DELETE FROM ${t}`).run();
      if (!rows.length) continue;
      const cols = Object.keys(rows[0]);
      const ph = cols.map(() => '?').join(',');
      const ins = db.prepare(`INSERT INTO ${t} (${cols.join(',')}) VALUES (${ph})`);
      for (const r of rows) ins.run(...cols.map((c) => r[c]));
    }
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}

function autoBackup() {
  const stamp = todayLocal();
  const name = `kashf-backup-${stamp}.json`;
  const full = path.join(BACKUP_DIR, name);
  if (fs.existsSync(full)) return null;
  fs.writeFileSync(full, JSON.stringify(exportAll(), null, 1));
  const files = fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.json')).sort();
  while (files.length > 30) fs.unlinkSync(path.join(BACKUP_DIR, files.shift()));
  return name;
}

function seedIfNeeded() {
  const n = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (n > 0) return false;
  const t = todayLocal();
  const iso = nowISO();
  const H = (pw) => bcrypt.hashSync(pw, 10);
  db.exec('BEGIN');
  try {
    const u = db.prepare('INSERT INTO users (name,username,pass_hash,role,shop_id,is_super,created_at) VALUES (?,?,?,?,?,?,?)');
    u.run('ایڈمن', 'admin', H('admin123'), 'admin', null, 1, iso);
    u.run('اسٹاف', 'staff', H('staff123'), 'staff', null, 0, iso);
    const sh = db.prepare('INSERT INTO shops (name,phone,address,whatsapp) VALUES (?,?,?,?)');
    const s1 = sh.run('المدینہ کریانہ اسٹور', '', 'مین بازار', '').lastInsertRowid;
    const s2 = sh.run('نیو مدینہ سویٹس', '', 'چاندنی چوک', '').lastInsertRowid;
    u.run('المدینہ کریانہ', 'shop1', H('shop123'), 'shop', s1, 0, iso);
    u.run('نیو مدینہ سویٹس', 'shop2', H('shop123'), 'shop', s2, 0, iso);
    const sup = db.prepare("INSERT INTO suppliers (name,phone,address) VALUES ('المدینہ ڈیری فارم','','')").run().lastInsertRowid;
    const p = db.prepare(`INSERT INTO products
      (name_ur,name_en,category,unit,purchase_rate,sale_rate,wholesale_rate,stock,low_threshold)
      VALUES (?,?,?,?,?,?,?,?,?)`);
    const prods = [
      ['کھویا', 'Khoya', 'ڈیری', 'کلو', 780, 850, 820, 40, 8],
      ['پنیر', 'Paneer', 'ڈیری', 'کلو', 1050, 1200, 1120, 12, 5],
      ['دہی', 'Dahi', 'ڈیری', 'کلو', 180, 220, 200, 60, 10],
      ['دیسی گھی', 'Desi Ghee', 'ڈیری', 'کلو', 2200, 2400, 2300, 15, 4],
      ['مکھن', 'Makhan', 'ڈیری', 'کلو', 900, 1050, 980, 20, 5],
    ];
    const pids = prods.map((r) => p.run(...r).lastInsertRowid);

    // sample purchases (supplier pays bilty)
    const mkPurchase = (date, items, bilty, paid, billNo) => {
      const sub = r2(items.reduce((a, i) => a + i[1] * i[2], 0));
      const total = sub; // supplier-paid bilty is NOT our cost
      const bal = r2(total - paid);
      const id = db.prepare(`INSERT INTO purchases
        (supplier_id,date,bill_no,subtotal,bilty_amt,bilty_paid_by,total,paid,balance,note,created_by,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(sup, date, billNo, sub, bilty, 'supplier', total, paid, bal, '', 1, iso).lastInsertRowid;
      const pi = db.prepare('INSERT INTO purchase_items (purchase_id,product_id,qty,rate,amount) VALUES (?,?,?,?,?)');
      const ps = db.prepare('UPDATE products SET stock = stock + ? WHERE id = ?');
      for (const [pid, qty, rate] of items) {
        pi.run(id, pid, qty, rate, r2(qty * rate)); ps.run(qty, pid);
      }
      return id;
    };
    mkPurchase('2026-10-01', [[pids[0], 20, 780], [pids[1], 10, 1050]], 500, 20000, 'PUR-001');
    mkPurchase('2026-10-05', [[pids[2], 40, 180], [pids[3], 8, 2200]], 400, 15000, 'PUR-002');

    // sample sales
    const mkSale = (date, ctype, shopId, items, bilty, petrol, disc, paid, method, note) => {
      const sub = r2(items.reduce((a, i) => a + i[1] * i[2], 0));
      const total = r2(sub + bilty + petrol - disc);
      const bal = r2(total - paid);
      const billNo = 'KHF-' + String(db.prepare('SELECT COALESCE(MAX(id),0)+1 n FROM sales').get().n).padStart(4, '0');
      const id = db.prepare(`INSERT INTO sales
        (bill_no,date,customer_type,shop_id,subtotal,bilty_amt,discount,expense_petrol,total,paid,balance,payment_method,note,created_by,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(billNo, date, ctype, shopId, sub, bilty, disc, petrol, total, paid, bal, method, note, 1, iso).lastInsertRowid;
      const si = db.prepare('INSERT INTO sale_items (sale_id,product_id,qty,rate,amount) VALUES (?,?,?,?,?)');
      const ps = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?');
      for (const [pid, qty, rate] of items) {
        si.run(id, pid, qty, rate, r2(qty * rate)); ps.run(qty, pid);
      }
      return id;
    };
    mkSale('2026-10-06', 'walkin', null, [[pids[0], 5, 850], [pids[2], 3, 220]], 200, 150, 0, 5410, 'cash', '');
    mkSale('2026-10-07', 'shop', s1, [[pids[1], 4, 1200], [pids[0], 6, 850]], 300, 200, 0, 3000, 'credit', '');
    mkSale(todayLocal(), 'shop', s2, [[pids[3], 2, 2400]], 250, 100, 0, 0, 'credit', '');

    const pay = db.prepare(`INSERT INTO ledger_payments
      (date,party_type,party_id,amount,method,direction,note,created_by) VALUES (?,?,?,?,?,?,?,?)`);
    pay.run('2026-10-07', 'shop', s1, 2000, 'cash', 'in', 'وصولی', 1);
    pay.run('2026-10-06', 'supplier', sup, 10000, 'bank', 'out', 'ادائیگی', 1);

    const ex = db.prepare('INSERT INTO expenses (date,category,amount,note,kind,created_by) VALUES (?,?,?,?,?,?)');
    ex.run('2026-10-02', 'کرایہ', 15000, 'دکان کرایہ', 'business', 1);
    ex.run('2026-10-03', 'بجلی بل', 3200, '', 'business', 1);
    ex.run('2026-10-05', 'تنخواہ', 25000, 'ملازم', 'business', 1);
    ex.run('2026-10-04', 'عطیہ', 2000, 'مسجد', 'personal', 1);
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); throw e; }
  return true;
}

module.exports = { db, todayLocal, nowISO, r2, exportAll, importAll, autoBackup, seedIfNeeded, BACKUP_DIR };
