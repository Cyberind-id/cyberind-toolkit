# Cyberind Toolkit

Cyberind Toolkit is a Cyberind-branded web port of the PocketPentester architecture, keeping the Rust engines behind an HTTP API and serving the Vue frontend from the same Vercel project.

## One Vercel project

This repository uses Vercel Services:

- `frontend/` — Vue 3 + Vite, served by Nginx in a Vercel container.
- `backend/` — Rust + Axum, built as a Vercel container.
- `/api/*` and `/health` are routed to the Rust backend.
- Everything else is routed to the frontend.

Vercel builds both services from this repository, so there is **one GitHub repository and one Vercel project**.

## Deploy

1. Upload the contents of this repository to GitHub.
2. In Vercel choose **Add New Project** and import the GitHub repository.
3. Keep the repository root as the project root.
4. Deploy. Vercel reads `vercel.json` and builds both services.

No Render/Railway backend is required.

## Important limitations

This is still server-side tooling. The Rust backend runs from Vercel's network, not from the user's phone/PC network.

- Internet-facing HTTP/DNS/TLS/TCP targets can be reached by the backend subject to Vercel/network limits.
- `LAN Map` cannot discover the user's private home/office LAN from a cloud Vercel container. It can only scan networks reachable from the Vercel execution environment. A local-agent architecture is required for true local-LAN discovery.
- Vercel containers are stateless. Files written by an engine are not durable. Persistent storage should be moved to a database/blob store if the feature needs durable data.
- Long-running scans are subject to Vercel Function/container execution limits.

Only use the security testing modules on systems you own or are explicitly authorized to test.
