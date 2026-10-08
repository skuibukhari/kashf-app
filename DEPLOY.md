# Kashf — Deploy on Alwaysdata

App: Bahi Khata & Inventory Management System (Express + SQLite backend, React frontend).
Repo layout:
```
kashf-app/
  server/        # Node.js backend (Express + node:sqlite). Run: node server.js
  server/data/   # kashf.db auto-created here on first boot (persists)
  server/backups/# dated auto-backup JSON files (kept 30 days)
  client/        # React + TypeScript + Tailwind frontend source
  client/dist/   # built frontend (already built — committed, no build step on host)
```

## Requirements on Alwaysdata
- **Node.js 22.5+** (uses built-in `node:sqlite` — no compilers, no native modules).
  In the Alwaysdata panel: Sites → your Node.js site → set Node version to 22 (or newer).
- Dependencies are pure JS (`express`, `bcryptjs`, `jsonwebtoken`).

## Deploy steps
1. Get the code on the server — either:
   - **Git:** push this folder to a GitHub repo, then on Alwaysdata: `ssh <user>@ssh-<account>.alwaysdata.net`, `git clone <repo>`, or
   - **Upload:** zip `kashf-app/` and upload via the Alwaysdata file manager / SFTP, then unzip.
2. SSH in and install backend deps (one time):
   ```bash
   cd ~/kashf-app/server
   npm install --production
   ```
3. Alwaysdata panel → **Web → Sites → Add a Node.js site**
   - Site address: `kashf.alwaysdata.net/kashf` (a **path** on your own domain —
     a separate `kashf-app.alwaysdata.net` address is rejected by the panel:
     "the domain name alwaysdata.net does not belong to you")
   - Working directory / application root: the `server/` folder (e.g. `~/kashf-app/server`)
   - Start file / command: `node server.js`
   - Environment:
     - `PORT=8100` (Alwaysdata gives you a port — use the one shown in the panel)
     - `JWT_SECRET=<a long random string>` (if unset, a dev default is used — set one!)
     - `BASE_PATH=/kashf` (REQUIRED when the site address has a path — the app
       mounts its API + frontend under it; the frontend build already uses
       relative asset paths and prefixes `/api` calls with `VITE_BASE_PATH`)
4. Start the site from the panel. First boot **seeds** the database:
   - `admin` / `admin123` (full access)
   - `staff` / `staff123`
   - `shop1` / `shop123` (demo shop portal)
   - Change these passwords immediately: login → Admin → Users.
5. Open the site URL. The API is at `/api`, the app at `/`.

## Notes
- SQLite file lives at `server/data/kashf.db` — it survives restarts; it is NOT in git by default (add `server/data/` to `.gitignore` if you git-push).
- A dated JSON auto-backup is written to `server/backups/` on every fresh boot (max 30 kept). One-click backup/restore is also in the app (Backup tab).
- Google Drive auto-upload is a stub (`POST /api/backup/drive` → 501). To enable: create a Google Cloud project + OAuth client, set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REFRESH_TOKEN` env vars, and implement the upload in `server/server.js` (see the code comments there).
- To rebuild the frontend after changes: `cd client && npm install && npm run build` (needs Node 18+ locally), then re-upload `client/dist/`.
  If the site address has a path (e.g. `/kashf`), build with the matching base:
  `VITE_BASE_PATH=/kashf npm run build` (at domain root, omit it).
