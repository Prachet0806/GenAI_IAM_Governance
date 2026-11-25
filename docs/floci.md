# Floci integration and scale tests

Floci 2.5.0 exercises the boto3 request/response path before live AWS. `common/aws_clients.py` routes clients, and discoveries record source `FLOCI`. Its default synthetic account is `111111111111`; set matching `AWS_ACCOUNT_ID` and `FLOCI_ACCOUNT_ID`. Floci health and the default `test/test` credentials do **not** prove AWS IAM semantics, effective access, least-privilege enforcement, throttling, or live readiness.

| Mode | `MOCK_IAM` | `SEEDED_IAM` | Source |
| --- | --- | --- | --- |
| Floci endpoint | `false` | `false` | `FLOCI` |
| Live AWS credential chain/endpoints | `true` | `false` | `AWS` |
| Offline seeded demo, no SDK calls | `false` | `true` | `MOCK` |

## Disposable SDK smoke test

With Docker Desktop running, use a disposable emulator:

```powershell
docker compose -f docker-compose.floci.yml up -d
$env:FLOCI_INTEGRATION = '1'
$env:MOCK_IAM = 'false'; $env:SEEDED_IAM = 'false'
$env:FLOCI_ENDPOINT_URL = 'http://127.0.0.1:4566'
$env:FLOCI_ACCOUNT_ID = '111111111111'; $env:AWS_ACCOUNT_ID = '111111111111'
.\.venv\Scripts\python.exe -m pytest -q tests/test_floci_integration.py
docker compose -f docker-compose.floci.yml down
```

The test creates a unique user, policy, and role, scans user/role paths through SDK clients, and verifies pinned observations in a temporary SQLite database. It does not reset emulator state. CI uses a fresh service container. For the OIDC-backed local stack, fill root `.env` from `.env.example` and run `docker compose up --build`; API uses internal `http://floci:4566`, with host access bound to loopback. Defaults keep GenAI off, `DRY_RUN=true`, and `ALLOW_EMULATOR_MUTATION=false`.

An emulator remediation exercise still needs an OIDC review decision and independent approval on a `FLOCI` snapshot. In a disposable stack set `APP_ENV=emulator`, `DRY_RUN=false`, `ENABLE_REMEDIATION=true`, `ALLOW_EMULATOR_MUTATION=true`, and a narrow `REMEDIATION_ALLOWLIST`; keep `ALLOW_LIVE_REMEDIATION=false`. Recreate the API container, then run `docker compose run --rm api python lambdas/remediation/handler.py`. The worker checks account/source, emulator health, approval, exact path, allowlist, and postflight observation. Live AWS requires `MOCK_IAM=true`, `SEEDED_IAM=false`, a real `AWS_ACCOUNT_ID`, and real credentials. Endpoint overrides are rejected; collect a **new AWS snapshot** because Floci evidence cannot authorize live remediation.

## Deterministic 100-user benchmark

`tests/fixtures/floci/profiles/baseline.json` and `tests/fixtures/floci/manifest.schema.json` define seed 42: 100 users (five without grants), four groups, six shared managed policies, 28 inline policies, 114 memberships, 109 managed attachments, and **357 distinct grant paths**. The runner checks exact `(principal, grant type, source, policy)` paths, document evidence, assessments, and one review per path. The seeder is namespace-idempotent and refuses unrelated identities because the scanner reads the whole account. Use an isolated in-memory Floci instance and a fresh application database per run.

```powershell
docker compose -f docker-compose.floci-benchmark.yml up -d
$env:MOCK_IAM = 'false'; $env:SEEDED_IAM = 'false'
$env:AWS_ACCOUNT_ID = '111111111111'; $env:FLOCI_ACCOUNT_ID = '111111111111'
.\.venv\Scripts\python.exe scripts/seed_floci_scale.py --profile baseline --seed 42 --output benchmarks/results/baseline-manifest.json --metrics-output benchmarks/results/baseline-seed.json
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/baseline-manifest.json --db-url sqlite:///benchmarks/results/sqlite-1.db --output benchmarks/results/sqlite-1.json
.\.venv\Scripts\python.exe benchmarks/create_pg_db.py --admin-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench --name iam_bench_1
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/baseline-manifest.json --db-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench_1 --output benchmarks/results/postgres-1.json
```

Repeat with fresh names (`-2`, `-3`) and the same fixture/image digest. Aggregate with `benchmarks/report.py <six-result-json-paths> --output-prefix benchmarks/results/baseline-summary`. It reports median/max stages, RSS, database size, versions, and counts; mixed seeds/source/image digests are rejected. `benchmarks/results/` is ignored by Git. This is a 100-user correctness baseline, not a capacity claim.

## Failure and SQL diagnostics

After seeding the isolated fixture, set `POSTGRES_TEST_URL=postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench` and run:

| Gate | Environment flag and command | What it proves locally |
| --- | --- | --- |
| Lifecycle | `FLOCI_LIFECYCLE=1`; `python -m pytest -q tests/test_floci_lifecycle.py tests/test_migrations.py` | Collection, validation, publication, overlap, and historical review behavior on SQLite/PostgreSQL. |
| B5 crash | `FLOCI_CRASH=1`; `python -m pytest -q tests/test_floci_lifecycle.py -k process_termination` | `os._exit(73)` before/during/after publication and restart recovery. A killed prepublication attempt can remain `RUNNING`; there is no automatic orphan cleanup. |
| B6 HTTP faults | `FLOCI_FAULTS=1`; `python -m pytest -q tests/test_floci_lifecycle.py -k http_faults` | Proxy-injected throttling, timeout, malformed XML, and truncated pagination preserve prior publication and allow a later recovery scan. A server falsely claiming a complete but omitted page still needs independent inventory consistency checks. |

In PowerShell set each opt-in as `$env:FLOCI_LIFECYCLE = '1'` (or `FLOCI_CRASH`/`FLOCI_FAULTS`), and set `$env:POSTGRES_TEST_URL` before invoking the test command. The lifecycle test creates/drops its own PostgreSQL schema.

For B0 SQL profiling, start `docker compose -f docker-compose.floci-benchmark.yml -f docker-compose.floci-profile.yml up -d`, seed the baseline, then run `benchmarks/run_floci_benchmark.py` against **new** SQLite and PostgreSQL databases with `--profile-risk`, for example `python benchmarks/run_floci_benchmark.py --manifest benchmarks/results/baseline-manifest.json --db-url sqlite:///benchmarks/results/b0-sqlite.db --output benchmarks/results/b0-sqlite.json --profile-risk`. The profile records normalized SQL counts, client elapsed and p95 times, row counts, transaction and stage time; PostgreSQL adds `pg_stat_statements` plan/execution time. Client time includes driver and transport, so client minus server is not a pure network measure. Compare canonical per-grant assessment/review signatures before and after an optimization. Preserve the original six-run baseline; the ignored `benchmarks/results/b0-risk-profile.md` contains the local diagnostic comparison.

Next gates are policy mutation during collection, role/Identity Center scale, 250/500/1,000-user profiles, and live AWS staging. Floci's FIS API reports experiment state; HTTP fault injection here uses the local proxy. [Floci images](https://floci.io/floci/configuration/docker-images/), [endpoints](https://floci.io/floci/configuration/endpoints/), [multi-account configuration](https://floci.io/floci/configuration/multi-account/).
