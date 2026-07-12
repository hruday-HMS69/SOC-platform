# SOC Platform
A small Rust backend that simulates the detection layer of a Security Operations Center (SOC). It accepts security events, runs a couple of detection rules against them, and stores any alerts that get triggered. It's not meant to be a full SIEM just the core log → detect → alert workflow.

## What it does

You send it a log event, a failed login, an SQL injection attempt, whatever through a POST request. The event gets saved to Postgres, and immediately checked against two rules:

- If it's a `failed_login` and the same source IP has failed 5+ times in the last 10 minutes, it raises a `high` severity "brute force" alert.
- If the event type is one of `sql_injection`, `xss_attempt`, `rce_attempt`, `privilege_escalation`, or `malware_detected`, it raises a `critical` alert right away, no threshold needed.

Any alerts that fire get saved alongside the log and are queryable through their own endpoint. There's also a basic auth layer on top you can register a user, log in, and get a JWT back though right now that token isn't actually required to hit any of the other endpoints (more on that in Future Improvements).

## Why I built this

Wanted to get more comfortable writing backend services in Rust, and didn't want to build another todo list or blog API to do it. I've always found the log → detection → alert pipeline that SOC tools use pretty interesting, so I picked a stripped-down version of that instead - something with actual logic to write (the bruteforce rule needs a time windowed DB query, for instance) rather than just CRUD. It also ended up being a decent portfolio piece since it's not the same project everyone else building a backend demo has.

## Features

- Log ingestion endpoint that accepts arbitrary event data (source IP, event type, message, severity, optional raw JSON payload)
- Two detection rules run automatically on every ingested log: bruteforce (time windowed, per-IP) and critical event type matching
- Alerts are persisted separately from logs and queryable on their own
- User registration/login with argon2 password hashing, JWT issued on login
- Structured logging via `tracing`,every ingested log and triggered alert gets logged
- DB migrations run automatically on startup, no manual migration step
- Small test suite covering the detection rules and JWT logic (6 tests)

## Tech stack

- Rust + Axum for the API
- PostgreSQL + SQLx for storage
- Argon2 + JWT for authentication
- tracing for structured logs
- Docker Compose for running Postgres locally
- jsonwebtoken issuing and verifying JWTs for the login flow.
- Anyhow,error propagation across the app; didn't need custom error types for something this size.

One thing worth mentioning: thiserror and the cors feature from tower-http are still in cargo.toml, but they're leftovers from an earlier version of the project.I haven't removed them yet.
## Project structure

```
SOC-platform/
├── Cargo.toml
├── docker-compose.yml       # Postgres only - the app itself runs via `cargo run`
├── migrations/
│   ├── 001_initial.sql      # log_events + alerts tables
│   └── 002_users.sql        # users table
└── src/
    ├── main.rs              # loads config, connects to DB, runs migrations, builds the router
    ├── config.rs            # env-var based config
    ├── api/
    │   └── handlers/
    │       ├── health.rs    # GET /health
    │       ├── auth.rs      # POST /auth/register, POST /auth/login
    │       ├── log.rs       # POST /api/logs, GET /api/logs
    │       └── alert.rs     # GET /api/alerts
    ├── auth/
    │   └── jwt.rs           # create_token / verify_token
    ├── db/
    │   └── queries.rs       # all raw SQL lives here
    ├── detection/
    │   └── rules.rs         # the two detection rules + run_all_rules()
    └── models/
        ├── user.rs
        ├── log_event.rs
        └── alert.rs
```

Handlers stay thin,they parse the request, call into `db` or `detection`, and shape the response. The rule logic in `detection/rules.rs` doesn't know anything about HTTP, which is what let me unit test it without spinning up a server or a database (for the rules that don't need one).

Request flow for log ingestion:

```mermaid
flowchart LR
    A[POST /api/logs] --> B[(Postgres: log_events)]
    B --> C{run_all_rules}
    C -->|failed_login x5 in 10min, same IP| D[brute force alert]
    C -->|critical event type| E[critical alert]
    D --> F[(Postgres: alerts)]
    E --> F
    F --> G[Response: log + alerts]
```

## Getting started

You'll need:
- Rust (Rust (stable,2021 edition anything reasonably recent should work))
- Docker + Docker Compose (for Postgres), or a Postgres instance running locally
- `cargo`

Clone it:
```bash
git clone https://github.com/hruday-HMS69/SOC-platform.git
cd SOC-platform
```

Start Postgres:
```bash
docker-compose up -d
```

Create a `.env` file in the project root:
```
DATABASE_URL=postgres://soc_user:project_demo@localhost:5432/soc_platform
JWT_SECRET= replace with a long random String
HOST=0.0.0.0
PORT=3000
RUST_LOG=soc_platform=debug,tower_http=debug
```

`JWT_SECRET` just needs to be long and random - `openssl rand -hex 32` works fine. The `DATABASE_URL` above matches the default user/password/db name in `docker-compose.yml`; if you change one, update the other to match.

Run it:
```bash
cargo run
```

This connects to Postgres, runs the migrations automatically, and starts the server on `http://0.0.0.0:3000` (or whatever `HOST`/`PORT` you set). Confirm it's up with:
```bash
curl http://localhost:3000/health
```

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | - | Postgres connection string |
| `JWT_SECRET` | yes | - | Used to sign and verify JWTs |
| `HOST` | no | `0.0.0.0` | |
| `PORT` | no | `3000` | |
| `RUST_LOG` | no | `soc_platform=debug,tower_http=debug` | Standard `tracing` env filter syntax |

## API reference

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/auth/register` | Create a user (`username`, `password`) - always assigned the `analyst` role |
| POST | `/auth/login` | Returns a JWT (24h expiry) on success |
| POST | `/api/logs` | Ingest a log event, runs detection rules against it |
| GET | `/api/logs?limit=` | List recent logs (default 50, max 500) |
| GET | `/api/alerts?limit=` | List recent alerts (default 50, max 500) |

Example - ingesting a log that trips the critical-event rule:
```bash
curl -X POST http://localhost:3000/api/logs \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "203.0.113.42",
    "event_type": "sql_injection",
    "message": "Detected UNION SELECT in login form",
    "severity": "high"
  }'
```

That returns the saved log plus a `critical` alert in the same response.

## Testing

```bash
cargo test
```

6 tests total - 3 covering the detection rules (`detection/rules.rs`)and, 3 covering JWT creation/verification (`auth/jwt.rs`). The brute-force rule itself isn't unit tested since it needs a live DB connection to count rows - would need a test DB setup to cover that properly.

## Future improvements

If I keep working on this, these are probably the next things I'd add:

- **Enforce auth on the protected routes.** `verify_token()` exists and is tested, but nothing calls it yet - `/api/logs` and `/api/alerts` are open to anyone right now. Adding middleware to check the `Authorization` header is the obvious next step.
- **Use the `role` field for something.** Every user gets `analyst` on registration and it's included in the JWT claims, but nothing actually checks it. Want an `admin` role that can do things analysts can't.
- **More detection rules.** Right now there are two. Things like impossible travel (same user, two distant IPs, short time window) or a general per-IP rate limit would be natural next additions.
- **Real pagination.** `LIMIT` with a max of 500 works fine for a demo, but a cursor or offset would be needed for actual use.
- **Rate limiting on the API itself** - especially `/auth/login`, which has no throttling right now.
- **Dockerize the app itself**, not just Postgres, so the whole thing runs with one `docker-compose up`.
- **CI** - GitHub Actions running `cargo test` and `cargo clippy` on every push.

## License

MIT - see [LICENSE](LICENSE) for the full text.