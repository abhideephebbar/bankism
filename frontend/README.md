# Bankism — Frontend

Cinematic React + TypeScript interface for the Bankism security core.
All security decisions come from the backend; the UI never determines verdicts.

## Run

```bash
npm install
npm run dev        # http://localhost:5173 (backend must run on :8000)
```

Other commands: `npm test` (vitest) · `npm run build` (type-check + production
build) · `npx tsc` (type-check only).

## Configuration

Copy `.env.example` to `.env` to point at a non-default backend:

```
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## Notes

* `Evaluate` returns a verdict only; `Process` asks the backend to execute and
  requires explicit confirmation. The UI keeps evaluation and execution strictly
  separate, handles stale verdicts, and never fabricates results on network
  failure (`EXECUTION STATUS UNKNOWN`).
* Accounts are created through `POST /api/v1/demo/users`; balances displayed in
  the UI always come from backend responses.
