# Floci IAM integration

Floci exercises the boto3 request and response path before a live AWS test. The repository pins `floci/floci:2.5.0`, sends every AWS-shaped client through `common/aws_clients.py`, and records `FLOCI` as the discovery source. Its default account is `111111111111`; the application requires `AWS_ACCOUNT_ID` to match `FLOCI_ACCOUNT_ID` in Floci mode. The seeded `MOCK` dataset remains available only through `SEEDED_IAM=true`.

| Mode | `MOCK_IAM` | `SEEDED_IAM` | Endpoint and credentials | Source recorded |
| --- | --- | --- | --- | --- |
| Floci | `false` | `false` | local Floci endpoint, static `test/test` | `FLOCI` |
| Live AWS | `true` | `false` | standard AWS profile/credential chain, AWS endpoints | `AWS` |
| Seeded demo | `false` | `true` | no SDK calls | `MOCK` |

## Disposable integration test

Start Docker Desktop, then from the repository root:

```bash
docker compose -f docker-compose.floci.yml up -d
FLOCI_INTEGRATION=1 MOCK_IAM=false SEEDED_IAM=false \
  FLOCI_ENDPOINT_URL=http://127.0.0.1:4566 \
  FLOCI_ACCOUNT_ID=111111111111 AWS_ACCOUNT_ID=111111111111 \
  python -m pytest -q tests/test_floci_integration.py
```

The test creates a uniquely named IAM user, managed policy, and role in Floci, scans user and role paths through the actual SDK clients, and verifies the pinned grant observations and `FLOCI` source. It uses a temporary SQLite database. It does not reset Floci state; use a disposable Floci instance. The CI workflow runs the same test with a fresh service container. Stop the standalone emulator with `docker compose -f docker-compose.floci.yml down`.

For a deterministic 100-user baseline with SQLite and Postgres measurements, follow [the scale benchmark](floci-scale-benchmark.md). It requires a dedicated Floci instance; do not run it in the same container as this smoke test.

For the full OIDC-backed Compose stack, copy `.env.example` to `.env`, fill the OIDC and frontend secrets, and run `docker compose up --build`. The API connects to `http://floci:4566` inside Compose. The `floci` service is exposed only on the host loopback address. The defaults keep `DRY_RUN=true` and `ALLOW_EMULATOR_MUTATION=false`. The separate emulator mutation path requires `APP_ENV=emulator` and an authenticated review and independent approval.

For a Floci remediation exercise, first run discovery, risk assessment, and a campaign against the synthetic account. Complete an OIDC reviewer decision and independent approval on that `FLOCI` snapshot. Then configure `APP_ENV=emulator`, `DRY_RUN=false`, `ENABLE_REMEDIATION=true`, `ALLOW_EMULATOR_MUTATION=true`, and a narrow `REMEDIATION_ALLOWLIST` in the local `.env`; keep `ALLOW_LIVE_REMEDIATION=false`. Recreate the API container so it reads the settings, then run `docker compose run --rm api python lambdas/remediation/handler.py`. The worker checks the source, account, Floci health, approval, exact path, allowlist, and postflight observation before recording a verified result. Use a disposable Floci instance for this test.

To use live AWS after emulator acceptance, set `MOCK_IAM=true`, `SEEDED_IAM=false`, a real `AWS_ACCOUNT_ID`, and an AWS profile or role credentials. The live client factory rejects `AWS_ENDPOINT_URL*` overrides and ignores endpoint URLs from AWS config files. Re-run discovery into a separate account/source snapshot: Floci observations are not eligible for live AWS remediation.

Floci health checks prove only that the emulator responds. The Floci test does not establish AWS IAM semantics, effective permissions, real OIDC, or live remediation readiness. Floci IAM policy enforcement is disabled by default, so it cannot be used to prove least-privilege access control.

References: [Floci Docker images](https://floci.io/floci/configuration/docker-images/), [control-plane and readiness endpoints](https://floci.io/floci/configuration/endpoints/), [multi-account configuration](https://floci.io/floci/configuration/multi-account/).
