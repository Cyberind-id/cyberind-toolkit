# Cyberind Toolkit — Vercel One Project

Cyberind-branded web toolkit based on the PocketPentester source, with the Rust engines exposed through an Axum HTTP API and a Vue 3 + Vite frontend.

## Architecture

- `frontend/` — Vue 3 + Vite web UI.
- `backend/` — Rust/Axum backend containing the port scan, subdomain, HTTP probe, takeover, SQLi, XSS, JWT, Xploiter, Auto-Pwn, LAN Map, repeater, fuzzing, DNS, TLS, banner, domain and other engines.
- `vercel.json` — Vercel Services configuration: Vite frontend + Rust container backend under one Vercel project/domain.

## Deploy

1. Upload the repository contents to GitHub with `vercel.json` at repository root.
2. Import the GitHub repository into Vercel.
3. Select the **Services** preset if Vercel asks for a preset.
4. Keep Root Directory as `./`.
5. Do not override Build Command, Install Command, or Output Directory at the project level.
6. Deploy.

The frontend uses same-origin `/api/...` requests, so no `VITE_API_URL` is required.

## Important

The backend container is stateless. Do not rely on its filesystem for permanent data. The LAN Map engine cannot see the end user's private Wi-Fi from Vercel; it scans from the cloud runtime. Use only on systems/networks where you have authorization.
