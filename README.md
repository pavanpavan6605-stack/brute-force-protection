# Brute Force IP Protection System

A full-stack college project. The original single-file page used browser `localStorage` and a simulated IP address. This version moves authentication and security decisions to a Node.js server and stores data in SQLite.

## Features

- User registration and login
- Password hashing with bcrypt (12 salt rounds); plaintext passwords are never stored
- Server-side sessions stored in SQLite
- Server-detected client IP (`req.ip`); no IP field is accepted from the browser
- Five failed login attempts from the same IP trigger a 24-hour IP block
- Successful login resets that IP's failed-attempt counter
- IP block records and user accounts persist in the SQLite database
- Admin account can view registered users and active IP blocks
- Helmet security headers, same-origin checks and an additional login request rate limiter
- Responsive dashboard

## Requirements

- Node.js 18 or newer
- npm

## Run locally (VS Code / Windows)

1. Extract this ZIP file.
2. Open the `brute-force-protection` folder in VS Code.
3. Open the VS Code terminal in that folder.
4. Install dependencies:

   ```bash
   npm install
   ```

5. Create your environment file:

   **Windows PowerShell**
   ```powershell
   Copy-Item .env.example .env
   ```

   **macOS / Linux**
   ```bash
   cp .env.example .env
   ```

6. Open `.env`. Change `SESSION_SECRET` to a long random value and change the admin password. The admin password must be at least 12 characters.
7. Start the application:

   ```bash
   npm start
   ```

8. Open **http://localhost:3000** in your browser. Do not open `public/index.html` directly; the Node server must be running.

## Test the project

1. Select **Create account**, register a normal user with a password of at least 8 characters, and sign in.
2. Sign out. Enter a wrong password five times from the same network/IP.
3. The server should reject the fifth attempt and block that IP for 24 hours. Refreshing the page or changing browser storage will not clear the block.
4. Try another account from the same IP: it should also be blocked, because the protection is IP-based.
5. Wait 24 hours for automatic expiry. A successful login before the threshold resets the failed-attempt count.
6. Sign in with the admin username/password configured in `.env` to view the admin overview.

## Project structure

```text
brute-force-protection/
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── data/                 # created automatically; contains SQLite DB and sessions
├── .env.example
├── .gitignore
├── package.json
├── server.js
└── README.md
```

## Important deployment notes

- Deploy this as a **Node.js web service**, not as a static GitHub Pages site. GitHub Pages cannot run the Express backend.
- Set the environment variables from `.env.example` in your hosting provider's dashboard. Never commit `.env`.
- If the host is behind a reverse proxy, set `TRUST_PROXY=1` only when you trust that proxy. This is needed on platforms such as Render so Express can identify the originating client IP correctly.
- SQLite needs persistent disk storage in production. Mount a persistent disk at the application's `data` directory. If the host does not provide persistent storage, the database and active blocks can be lost when the instance is replaced or redeployed. For production-scale hosting, use a managed database such as PostgreSQL.
- HTTPS is required in production because session cookies are marked `Secure` when `NODE_ENV=production`.

## Limitations / security notes for project demonstration

IP-based blocking can affect multiple legitimate users who share one public IP (for example, a college Wi-Fi network). Attackers can also change networks. Real deployments usually combine per-account throttling, per-IP throttling, monitoring, MFA and recovery controls. This project demonstrates the requested IP-based policy; it is not a substitute for a professional security review.
