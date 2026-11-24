# Floci IAM benchmark: 100-user baseline

This benchmark runs against the `upgrade` checkout's actual IAM user scanner, risk evaluator, and campaign generator. It uses an isolated Floci 2.5.0 instance and a separate Postgres 17 container. The ordinary one-user/one-role integration test stays fast and independent.

## Contract

The deterministic baseline profile is [baseline.json](../tests/fixtures/floci/profiles/baseline.json); the manifest format is [manifest.schema.json](../tests/fixtures/floci/manifest.schema.json). With seed 42, it creates 100 users (five with no grants), four groups, six shared managed policies, 28 inline policies, 114 memberships, 109 managed-policy attachments, and 357 unique user grant paths. A shared policy definition can produce many paths. The benchmark checks the exact `(principal, grant type, source, policy)` set, complete policy evidence, complete risk assessment, and one persisted review per path.

The seeder is idempotent for its own namespace. It refuses unrelated users, groups, or roles in the emulator because a whole-account scan would otherwise collect them. Reuse the same Floci fixture for SQLite and Postgres runs; use a fresh application database for every run. The standalone benchmark Compose file uses Floci's in-memory mode, so stopping the container discards its IAM state.

## Run locally in PowerShell

From the repository root, with Docker Desktop running:

```powershell
docker compose -f docker-compose.floci-benchmark.yml up -d
$env:MOCK_IAM = 'false'
$env:SEEDED_IAM = 'false'
$env:AWS_ACCOUNT_ID = '111111111111'
$env:FLOCI_ACCOUNT_ID = '111111111111'
.\.venv\Scripts\python.exe scripts/seed_floci_scale.py --profile baseline --seed 42 --output benchmarks/results/baseline-manifest.json --metrics-output benchmarks/results/baseline-seed.json
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/baseline-manifest.json --db-url sqlite:///benchmarks/results/sqlite-1.db --output benchmarks/results/sqlite-1.json
.\.venv\Scripts\python.exe benchmarks/create_pg_db.py --admin-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench --name iam_bench_1
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/baseline-manifest.json --db-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench_1 --output benchmarks/results/postgres-1.json
```

Use new `sqlite-2.db`, `sqlite-3.db` and `iam_bench_2`, `iam_bench_3` names for two more runs per backend. Then aggregate the six JSON results:

```powershell
.\.venv\Scripts\python.exe benchmarks/report.py benchmarks/results/sqlite-1.json benchmarks/results/sqlite-2.json benchmarks/results/sqlite-3.json benchmarks/results/postgres-1.json benchmarks/results/postgres-2.json benchmarks/results/postgres-3.json --output-prefix benchmarks/results/baseline-summary
```

Results under `benchmarks/results/` are ignored by Git. The report gives median and maximum stage times, peak process RSS, database size, source and image version, and exact counts. Pass `--image-digest` to the runner after reading `docker image inspect floci/floci:2.5.0 --format '{{index .RepoDigests 0}}'` if image-level provenance is needed. Keep the same digest for every comparable run. The report refuses results from different fixture seeds, source content, Floci versions, or image digests.

The first 100-user run is a correctness gate, not a capacity claim. Extend the fixture only after this baseline passes. Remaining gates include policy changes during collection, role scope, Identity Center scope, larger profiles, and emulator-side failures. Floci does not reproduce AWS network latency, throttling, or least-privilege authorization with the default `test/test` credential. Live AWS staging remains a separate acceptance step.

## Interruption and overlap acceptance

The opt-in lifecycle test uses the same seeded 100-user fixture and the actual IAM discovery handler. It runs against isolated SQLite and PostgreSQL databases, and injects failures at collection, validation, publication, and post-publication audit boundaries. It also pauses an older scan while a newer scan publishes or fails. Assertions cover current source publication, persisted collection versus publication outcomes, campaign eligibility, and historical review counts.

Run this against the disposable benchmark Compose stack after seeding the baseline profile:

```powershell
$env:FLOCI_LIFECYCLE = '1'
$env:POSTGRES_TEST_URL = 'postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench'
.\.venv\Scripts\python.exe -m pytest -q tests/test_floci_lifecycle.py tests/test_migrations.py
```

The PostgreSQL test creates and drops its own schema. The SQLite test uses a temporary database. The Floci instance must contain only the baseline manifest, so use the isolated in-memory Compose stack. These lifecycle tests inject application-side failures and deterministic thread barriers; the separate B5 and B6 tests below cover process termination and HTTP faults. The migration tests exercise comment-only, mixed-comment, multiple-statement, and empty-statement SQL on both backends.

## B5: process termination

`FLOCI_CRASH=1` runs a separate worker against the actual seeded Floci inventory. The parent kills it with `os._exit(73)` after collection and before publication, during an uncommitted publication, and after publication commits but before audit logging. It checks the persisted receipt, attempt status, publication pointer, historical reviews, and a fresh recovery scan on both databases.

```powershell
$env:FLOCI_CRASH = '1'
$env:POSTGRES_TEST_URL = 'postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench'
.\.venv\Scripts\python.exe -m pytest -q tests/test_floci_lifecycle.py -k process_termination
```

An abruptly killed pre-publication attempt retains `RUNNING` as its last persisted status until a new attempt supersedes it; its validated collection receipt survives. The outcome API then reports successful collection with superseded publication. There is no worker lease or automatic orphan-status reconciliation yet, so B5 establishes evidence safety and restart recovery, not terminal attempt-state cleanup.

## B6: HTTP fault injection in front of Floci

Floci's FIS management API simulates experiment state rather than injecting faults into IAM. The local test proxy forwards normal requests to the real emulator and changes selected IAM responses. The test covers persistent throttling, a response timeout, malformed XML, and a truncated `ListUsers` page without a continuation marker. Every case must leave the prior publication intact and the new attempt failed; a subsequent unmodified scan must recover.

```powershell
$env:FLOCI_FAULTS = '1'
$env:POSTGRES_TEST_URL = 'postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench'
.\.venv\Scripts\python.exe -m pytest -q tests/test_floci_lifecycle.py -k http_faults
```

The missing-marker check rejects a malformed truncated page. A server that falsely reports `IsTruncated=false` while silently omitting users cannot be detected from that page alone; an independent inventory count or source consistency check is still needed for that fault model.

## B0: risk-stage SQL profile

Start the benchmark stack with the profile override so PostgreSQL preloads `pg_stat_statements`. This changes only the disposable benchmark Postgres configuration; the existing six-run baseline files are not rewritten.

```powershell
docker compose -f docker-compose.floci-benchmark.yml -f docker-compose.floci-profile.yml up -d
$env:MOCK_IAM = 'false'
$env:SEEDED_IAM = 'false'
$env:AWS_ACCOUNT_ID = '111111111111'
$env:FLOCI_ACCOUNT_ID = '111111111111'
.\.venv\Scripts\python.exe scripts/seed_floci_scale.py --profile baseline --seed 42 --output benchmarks/results/b0-manifest.json --metrics-output benchmarks/results/b0-seed.json
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/b0-manifest.json --db-url sqlite:///benchmarks/results/b0-after-sqlite.db --output benchmarks/results/b0-after-sqlite.json --profile-risk
.\.venv\Scripts\python.exe benchmarks/create_pg_db.py --admin-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench --name iam_bench_b0_after
.\.venv\Scripts\python.exe benchmarks/run_floci_benchmark.py --manifest benchmarks/results/b0-manifest.json --db-url postgresql://iam_bench:iam_bench@127.0.0.1:55432/iam_bench_b0_after --output benchmarks/results/b0-after-postgres.json --profile-risk
```

Use new database and output names for every run. The `--profile-risk` flag adds normalized SQL counts, client elapsed time, average and p95 latency, driver row counts, transaction duration, and total SQL time versus stage wall time. For PostgreSQL it also records `pg_stat_statements` planning and execution time. Client SQL time includes driver work, transport, and server work; subtracting server time does not give a pure network measurement. The report script compares before/after runs and verifies a canonical per-grant assessment and review signature across both backends. See the local ignored artifact `benchmarks/results/b0-risk-profile.md` for the current single-run diagnostic comparison.
