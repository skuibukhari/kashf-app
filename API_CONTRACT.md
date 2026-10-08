# Kashf API Contract (backend: ~/workspace/kashf-app/server/server.js)

Base: same origin, prefix `/api`. Auth header: `Authorization: Bearer <token>`.
Token stored in localStorage as `kashf_token`. Dates are `YYYY-MM-DD` strings.
Error shape: `{ error: 'CODE', product?, available? }`.

## Auth
- `POST /api/auth/login` `{username,password}` → `{token, user:{id,name,username,role,shop_id}}`
- `GET /api/auth/me` → `{id,name,username,role,shop_id}` (role: admin|staff|shop)

## Users (admin only)
- `GET /api/users` → `[{id,name,username,role,shop_id,disabled,created_at}]`
- `POST /api/users` `{name*,username*,password*,role*,shop_id?}` → `{id}`
- `PUT /api/users/:id` `{name?,password?,role?,shop_id?,disabled?}` → `{ok:true}`
- `DELETE /api/users/:id` → `{ok:true}`

## Shops / Suppliers
- `GET /api/shops` (shop role → only own shop) / `POST {name*,phone,address,whatsapp}` / `PUT /:id` / `DELETE /:id` (admin)
- `GET /api/suppliers` / `POST {name*,phone,address}` / `PUT /:id` / `DELETE /:id` (admin)

## Products (admin/staff)
- `GET /api/products` → `[{id,name_ur,name_en,sku,barcode,category,unit,purchase_rate,sale_rate,wholesale_rate,stock,low_threshold,disabled}]`
- `POST` same fields (`name_ur*`) → `{id}`; `PUT /:id`; `DELETE /:id` (admin)

## Purchases (admin/staff)
- `GET /api/purchases?from&to&supplier_id` → `[{...,supplier_name}]`
- `GET /api/purchases/:id` → `{..., items:[{product_id,qty,rate,amount,name_ur,unit}]}`
- `POST` `{supplier_id*,date*,bill_no?,items*:[{product_id,qty,rate}],bilty_amt,bilty_paid_by:'supplier'|'us',paid,note}` → `{id}`
  (supplier-paid bilty is recorded but NOT added to total)
- `PUT /:id` (admin), `DELETE /:id` (admin, reverses stock)

## Sales (admin/staff create; shop reads own)
- `GET /api/sales?from&to&shop_id&q` → `[{...,shop_name}]`
- `GET /api/sales/:id` → `{..., items:[{product_id,qty,rate,amount,name_ur,unit,purchase_rate}]}`
- `POST` `{date*,customer_type:'walkin'|'shop',shop_id?,items*:[{product_id,qty,rate}],bilty_amt,discount,expense_petrol,paid,payment_method:'cash'|'easypaisa'|'bank'|'credit',note}` → `{id}`
  total = subtotal + bilty_amt + expense_petrol − discount. Fails 400 `INSUFFICIENT_STOCK` with `{product, available}`.
- `PUT /:id` (admin), `DELETE /:id` (admin)

## Payments / Expenses (admin/staff)
- `GET /api/payments?from&to&party_type&party_id` / `POST {date*,party_type*:'shop'|'supplier',party_id*,amount*,method,direction*:'in'|'out',note}` / `PUT /:id` / `DELETE /:id` (admin)
- `GET /api/expenses?from&to&kind` / `POST {date*,category*,amount*,note,kind:'business'|'personal'}` / `PUT /:id` / `DELETE /:id` (admin)

## Dashboard / Reports
- `GET /api/dashboard/stats` →
  admin/staff: `{todaySales,weeklySales,monthlyTurnover,receivables,payables,lowStock:[{id,name_ur,name_en,stock,low_threshold,unit}],netProfit,savings,weekly:[{date,revenue,expenses,profit}]×7}`
  shop: `{shop:true,balance,recent:[{id,bill_no,date,total,paid,balance}]}`
- `GET /api/reports/pnl?from&to` → `{from,to,revenue,cogs,grossProfit,businessExpenses,personalExpenses,netProfit,savings,byCategory:[{category,v}]}`
- `GET /api/reports/ledger?party_type&party_id&from&to` → `{opening,rows:[{date,desc,debit,credit,balance}],closing}`
  (shop: debit=bill totals they owe, credit=payments received; supplier: credit=purchases we owe, debit=payments we made)
- `GET /api/reports/cashsales?from&to&q` → `[{id,bill_no,date,total,payment_method,shop_name,items,margin}]`

## Backup
- `GET /api/backup/export` → JSON file download (all tables)
- `POST /api/backup/import` `{data}` (admin) → `{ok:true}`
- `GET /api/backup/list` → `[{name,size}]`; `GET /api/backup/file/:name` → download
- `POST /api/backup/drive` → 501 stub (Drive not configured)
