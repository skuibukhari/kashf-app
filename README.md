# Kashf — بہی کھاتہ و انوینٹری مینجمنٹ سسٹم

Bilingual (Urdu default, RTL + English toggle) Bahi Khata & inventory app for a dairy
business (khoya, paneer, dahi, desi ghee…). Navy + gold royal theme, dark/light mode.

## Run locally
```bash
cd server && npm install && node server.js   # API on :3000, serves client/dist
# frontend rebuild (if you change client/):
cd client && npm install && npm run build
```
First boot seeds demo data + logins: `admin/admin123`, `staff/staff123`,
`shop1/shop123`, `shop2/shop123`. Change passwords after first login.

## Business rules (as specified by the owner)
- **Purchase:** supplier pays the bilty (freight). `bilty_amt` is recorded but NOT added
  to our purchase cost (unless `bilty_paid_by='us'`).
- **Sale:** WE pay bilty + petrol. Both are added to the bill total (charged to the
  customer) and counted as our cost in margin math, so bill profit = subtotal − discount − COGS.
- **Personal expenses** (donation etc., `kind='personal'`) are NEVER part of business P&L.
  Dashboard shows **Net Profit/Loss** and **Savings** as separate cards
  (Savings = Net Profit − Personal expenses).
- **Shop portal:** shop users see ONLY their own shop's ledger/bills (server-enforced).

## Structure
```
server/
  server.js       # Express app, all /api routes, serves client/dist
  db.js           # node:sqlite schema, seed data, backup helpers
  data/kashf.db   # SQLite (auto-created, git-ignored)
  backups/        # dated auto-backups (30 kept)
client/
  src/            # React + TS + Tailwind source
  dist/           # built app (served by server.js)
API_CONTRACT.md   # exact REST contract the frontend was built against
DEPLOY.md         # Alwaysdata deploy steps
```

## Main API (see API_CONTRACT.md for the full contract)
`POST /api/auth/login` · CRUD `/api/users /shops /suppliers /products`
`/api/purchases` · `/api/sales` (stock auto-adjusted in transactions)
`/api/payments` · `/api/expenses` · `GET /api/dashboard/stats`
`GET /api/reports/pnl|ledger|cashsales` · `/api/backup/export|import|list`
