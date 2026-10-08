# Kashf API Contract (backend: ~/workspace/kashf-app/server/server.js)

Base: same origin, prefix `/api`. Auth header: `Authorization: Bearer <token>`.
Token stored in localStorage as `kashf_token`. Dates are `YYYY-MM-DD` strings.
Error shape: `{ error: 'CODE', product?, available? }`.

## Auth
- `POST /api/auth/login` `{username,password}` → `{token, user:{id,name,username,role,shop_id}}`
- `GET /api/auth/me` → `{id,name,username,role,shop_id}` (role: admin|staff|shop)

## Users (admin only)
- `GET /api/users` → `[{id,name,username,role,shop_id,disabled,is_super,created_at}]`
- `POST /api/users` `{name*,username*,password*,role*,shop_id?}` → `{id}` (role=admin requires super admin → 403 SUPER_ONLY)
- `PUT /api/users/:id` `{name?,password?,role?,shop_id?,disabled?}` → `{ok:true}` (super admin account untouchable by others → 403 SUPER_PROTECTED; fellow admins managed by super only → 403 ADMINS_BY_SUPER_ONLY)
- `DELETE /api/users/:id` → `{ok:true}` (super admin can never be deleted)
- Main (super) admin: the seeded `admin` user (is_super=1, shown with 🔒). Only the super admin can create admin users, change admin passwords, or disable/delete admins. Other admins can fully manage staff/shop users and shops.

## Shops / Suppliers
- `GET /api/shops` (shop role → only own shop) / `POST {name*,phone,address,whatsapp}` / `PUT /:id` / `DELETE /:id` (admin)
- `GET /api/suppliers` / `POST {name*,phone,address}` / `PUT /:id` / `DELETE /:id` (admin)

## Products (admin/staff)
- `GET /api/products` → `[{id,name_ur,name_en,sku,barcode,category,unit,purchase_rate,sale_rate,wholesale_rate,stock,low_threshold,disabled}]`
- `POST` same fields (`name_ur*`) → `{id}`; `PUT /:id`; `DELETE /:id` (admin)

## Purchases (admin/staff)
- `GET /api/purchases?from&to&supplier_id` → `[{...,supplier_name}]`
- `GET /api/purchases/:id` → `{..., items:[{product_id,qty,rate,amount,name_ur,unit}]}`
- `POST` `{supplier_id*,date*,bill_no?,items*:[{product_id,qty,rate}],bilty_amt,bilty_paid_by:'supplier'|'us',paid,account_id,note}` → `{id}`
  (supplier-paid bilty is recorded but NOT added to total; paid>0 ⇒ account_id required)
- `PUT /:id` (admin), `DELETE /:id` (admin, reverses stock)

## Sales (admin/staff create; shop reads own)
- `GET /api/sales?from&to&shop_id&q` → `[{...,shop_name}]`
- `GET /api/sales/:id` → `{..., items:[{product_id,qty,rate,amount,name_ur,unit,purchase_rate}], account_name}`
- `POST` `{date*,customer_type:'walkin'|'shop',shop_id?,items*:[{product_id,qty,rate}],discount,paid,account_id,note,manual_expenses?:[{category,amount}],expense_account_id?}` → `{id}`
  total = subtotal − discount (bilty/petrol NEVER in bill; manual expenses become separate `expenses` rows linked by `sale_id`).
  paid>0 ⇒ account_id required & valid; paid=0 ⇒ account_id must be null. Fails 400 `INSUFFICIENT_STOCK` with `{product, available}`.
- `PUT /:id` (admin), `DELETE /:id` (admin)

## Wallet accounts (بٹوہ)
- `GET /api/accounts` (admin/staff) → `[{id,name_ur,name_en,type,disabled,opening,inflow,outflow,balance}]` (balance computed)
- `POST /api/accounts` (admin) `{name_ur*,name_en,type:'cash'|'easypaisa'|'jazzcash'|'bank'|'other',opening_balance}` → `{id}`
- `PUT /api/accounts/:id` (admin) `{name_ur?,name_en?,type?,opening_balance?,disabled?}` → `{ok:true}`
- `GET /api/accounts/:id/statement?from&to` → `{account,from,to,rows:[{date,ref,desc,rin,rout,balance}],closing}`

## Payments / Expenses (admin/staff)
- `GET /api/payments?from&to&party_type&party_id` → `[{...,voucher_no,account_name,party_name}]`
- `GET /api/payments/:id` → voucher detail `{...,voucher_no,party_name,account_name}`
- `POST` `{date*,party_type*:'shop'|'supplier',party_id*,direction*:'received'|'paid',amount*,account_id*,note}` → `{id,voucher_no}` (stored direction 'in'/'out')
- `PUT /:id` `{date?,amount?,direction?,note?,account_id?}` / `DELETE /:id` (admin)
- `GET /api/expenses?from&to&kind` / `POST {date*,category*,amount*,note,kind:'business'|'personal',account_id*}` / `PUT /:id` / `DELETE /:id` (admin)
- Shops/suppliers accept `opening_balance` (+ve: shop owes us / we owe supplier)

## Dashboard / Reports
- `GET /api/dashboard/stats` →
  admin/staff: `{todaySales,weeklySales,monthlyTurnover,receivables,payables,lowStock:[{id,name_ur,name_en,stock,low_threshold,unit}],netProfit,savings,weekly:[{date,revenue,expenses,profit}]×7,wallets:[...],walletTotal}`
  shop: `{shop:true,balance,recent:[{id,bill_no,date,total,paid,balance}]}` (balance includes shop opening)
- `GET /api/reports/pnl?from&to` → `{from,to,revenue,cogs,grossProfit,businessExpenses,personalExpenses,netProfit,savings,byCategory:[{category,v}]}`
- `GET /api/reports/ledger?party_type&party_id&from&to` → `{opening,rows:[{date,desc,debit,credit,balance}],closing}`
  (first row is always the opening balance; at-bill/at-purchase payments appear as their own rows;
  shop: debit=bill totals they owe, credit=payments received; supplier: credit=purchases we owe, debit=payments we made)
- `GET /api/reports/cashsales?from&to&q` → `[{id,bill_no,date,total,payment_method,shop_name,items,margin}]` (paid>0 sales)

## Backup
- `GET /api/backup/export` → JSON file download (all tables)
- `POST /api/backup/import` `{data}` (admin) → `{ok:true}`
- `GET /api/backup/list` → `[{name,size}]`; `GET /api/backup/file/:name` → download
- `POST /api/backup/drive` → 501 stub (Drive not configured)

## Admin
- `POST /api/admin/wipe` `{confirm:'DELETE'}` (admin) → `{ok:true,backup}` — writes a pre-wipe JSON backup,
  then deletes all transactions (sales, sale_items, purchases, purchase_items, ledger_payments, expenses),
  resets product stock and party opening balances to 0. Keeps users/products/shops/suppliers/accounts.
