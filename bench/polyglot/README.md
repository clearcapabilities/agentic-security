# Polyglot Benchmark (P1.4 / G3)

Measures cross-language taint propagation. Each case is a small multi-service
project where a tainted request flows from one runtime to another through a
well-defined boundary (HTTP, gRPC, GraphQL, message queue, or ORM round-trip),
ending at a sensitive sink in a different language than where the request
arrived.

The scanner must:

1. Detect the original SAST finding at the sink.
2. Emit a `cross_language: true` chain finding at the entry point so a
   developer reading the entry code sees the transitive risk.

We measure F1 across all cases. PRD G3 target: ≥ 0.85.

## Layout

```
bench/polyglot/
├── README.md
├── runner.mjs                 # invokes scanner per case, computes F1
├── cases/
│   ├── 01-rest-node-to-python-sql/
│   │   ├── manifest.yaml      # case description + expected findings
│   │   ├── services/
│   │   │   ├── node/          # entry-point service (Express)
│   │   │   └── python/        # sink-side service (Flask)
│   │   └── openapi.yaml       # cross-language bridge
│   ├── 02-queue-node-to-python-cmd/
│   │   ├── manifest.yaml
│   │   └── services/...
│   └── 03-orm-roundtrip-write-read/
│       ├── manifest.yaml
│       └── services/...
└── results/                   # written by runner.mjs
```

## Manifest schema

```yaml
case: "01-rest-node-to-python-sql"
description: "HTTP POST → Python service → SQL injection"
flow:
  - service: node
    role: entry
    runtime: nodejs22
  - service: python
    role: sink
    runtime: python3.12
  boundary: openapi
expected:
  - file: services/python/app.py
    line: 14
    family: sql-injection
    severity: high
  - file: services/node/server.js
    line: 8
    family: sql-injection
    cross_language: true
```

## Running

```sh
npm run bench:polyglot           # all cases
npm run bench:polyglot -- --case 01-rest-node-to-python-sql   # one case
npm run bench:polyglot -- --json  # machine-readable output
```

## Status

v0.50.0 ships **3 starter cases** (HTTP→HTTP, queue→handler, ORM round-trip).
Remaining 7 cases queued for Phase-1 finalization:

- 04 HTTP→gRPC
- 05 HTTP→GraphQL
- 06 HTTP→GraphQL→DB
- 07 Multi-repo composition
- 08 Kafka producer → Java consumer
- 09 RabbitMQ producer → Python consumer
- 10 IaC-exposed Lambda → app code

The cases that exist are deliberately simple — single tainted field, single
boundary crossing. Real-world flows are harder; the curated benchmark grows
case-by-case so the F1 number stays interpretable.
