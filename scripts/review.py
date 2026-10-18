#scripts/review.py
"""Reviewer CLI (local demo polish). Thin wrapper over common/repo.py.

Maps 1:1 to future API:
  list   -> GET /reviews?status=&risk=&user=
  decide -> POST /reviews/{id}/decision {decision, comment, reviewer}
  stats  -> GET /reviews/stats
  audit  -> GET /audit-logs?limit=

No business logic here beyond arg parsing + rich rendering; all DB
access goes through common.db / common.repo.
"""
import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, repo
from common.db import db

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover
    print("rich is required: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)

console = None  # lazy per-call so pytest capsys captures output


def _console() -> "Console":
    from rich.console import Console as _C
    return _C(file=sys.stdout, width=200)


def _ai_marker(ai_summary, source=None) -> str:
    if not ai_summary or not source:
        return "-"
    if source == "FALLBACK":
        return "· fallback"
    return "✦ live"


def cmd_list(args) -> int:
    with db.get_connection() as conn:
        rows = repo.fetch_reviews_for_export(conn)
    filtered = []
    for r in rows:
        review_id, _camp, user, role, risk, status, _comment, ai, _ca, _ra, _rem = r[:11]
        if args.status and status != args.status:
            continue
        if args.risk and risk != args.risk:
            continue
        if args.user and args.user.lower() not in user.lower():
            continue
        filtered.append(r)
    table = Table(title=f"Access Reviews ({len(filtered)}/{len(rows)})")
    for col in ("Review", "User", "Role", "Risk", "Status", "AI", "Comment"):
        table.add_column(col, overflow="fold")
    for r in filtered:
        review_id, _c, user, role, risk, status, comment, ai, _ca, _ra, _rem = r[:11]
        style = "red" if risk == "HIGH" else ("yellow" if risk == "MEDIUM" else "green")
        source = r[11] if len(r) > 11 else None
        table.add_row(review_id[:8], user, role, f"[{style}]{risk}[/{style}]",
                      status, _ai_marker(ai, source), (comment or "")[:60])
    _console().print(table)
    return 0


def cmd_decide(args) -> int:
    decision = args.decision.upper()
    if decision not in ("APPROVED", "REVOKED"):
        _console().print(f"[red]decision must be APPROVED or REVOKED[/red]")
        return 2
    if decision == "REVOKED" and not (args.comment or "").strip():
        _console().print("[red]REVOKED requires --comment (DB CHECK enforces this)[/red]")
        return 2
    if os.getenv("APP_ENV", "development").lower() == "production":
        _console().print("[red]production decisions are disabled until an authenticated review service is integrated[/red]")
        return 2
    if not config.is_mock_iam():
        _console().print("[red]unauthenticated CLI decisions are restricted to MOCK_IAM=true demo data[/red]")
        return 2
    reviewer = args.reviewer or "local-demo"
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(cur, "SELECT status FROM access_reviews WHERE review_id = ?", (args.review_id,))
        row = cur.fetchone()
        if not row:
            _console().print(f"[red]review not found: {args.review_id}[/red]")
            return 1
        if row[0] != "PENDING":
            _console().print(f"[red]already decided ({row[0]}); refusing double-decide[/red]")
            return 1
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            cur,
            """UPDATE access_reviews SET status = ?, reviewer_comment = ?, reviewed_at = ?
               WHERE review_id = ? AND status = 'PENDING'""",
            (decision, args.comment or "", now, args.review_id),
        )
        if cur.rowcount == 0:
            _console().print("[red]update raced or already decided[/red]")
            return 1
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
            "review_decision", decision, f"{decision} by {reviewer}",
            entity_type="access_review", entity_id=args.review_id,
            details={"review_id": args.review_id, "decision": decision,
                     "reviewer": reviewer, "comment": args.comment or ""},
        )
    _console().print(f"[green]{decision}[/green] {args.review_id[:8]} by {reviewer}")
    return 0


def cmd_stats(args) -> int:
    with db.get_connection() as conn:
        rows = repo.fetch_reviews_for_export(conn)
    by_status: dict = {}
    by_risk: dict = {}
    for r in rows:
        by_status[r[5]] = by_status.get(r[5], 0) + 1
        by_risk[r[4]] = by_risk.get(r[4], 0) + 1
    table = Table(title=f"Review stats ({len(rows)} total)")
    table.add_column("Dimension")
    table.add_column("Value")
    table.add_column("Count")
    for k, v in sorted(by_status.items()):
        table.add_row("status", k, str(v))
    for k, v in sorted(by_risk.items()):
        table.add_row("risk", k, str(v))
    _console().print(table)
    return 0


def cmd_audit(args) -> int:
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(
            cur,
            "SELECT timestamp, level, action, status, entity_id, message FROM audit_logs "
            "ORDER BY timestamp DESC LIMIT ?",
            (args.tail,),
        )
        rows = cur.fetchall()
    table = Table(title=f"Audit log (latest {len(rows)})")
    for col in ("Timestamp", "Level", "Action", "Status", "Entity", "Message"):
        table.add_column(col, overflow="fold")
    for ts, level, action, status, entity_id, message in rows:
        table.add_row(str(ts)[:19], level or "", action or "", status or "",
                      (entity_id or "")[:8], (message or "")[:80])
    _console().print(table)
    if not rows:
        _console().print("[dim]no audit rows yet — run the demo pipeline first[/dim]")
    return 0


def cmd_auto_demo(args) -> int:
    """Deterministic demo decisions: revoke admin/super HIGH, approve LOW; leave MEDIUM pending."""
    if os.getenv("APP_ENV", "development").lower() == "production":
        _console().print("[red]auto-demo is disabled in production[/red]")
        return 2
    if not config.is_mock_iam():
        _console().print("[red]auto-demo requires MOCK_IAM=true[/red]")
        return 2
    with db.get_connection() as conn:
        cur = conn.cursor()
        db.execute(
            cur,
            """UPDATE access_reviews SET status='REVOKED',
                   reviewer_comment='Violation of Least Privilege', reviewed_at=CURRENT_TIMESTAMP
               WHERE status='PENDING' AND role_id IN
                   (SELECT role_id FROM roles WHERE role_name LIKE '%AdministratorAccess%'
                     OR role_name LIKE '%SuperUser%')""",
        )
        revoked = cur.rowcount
        db.execute(
            cur,
            """UPDATE access_reviews SET status='APPROVED',
                   reviewer_comment='Approved: read-only business need', reviewed_at=CURRENT_TIMESTAMP
               WHERE status='PENDING' AND role_id IN
                   (SELECT role_id FROM roles WHERE risk_level='LOW')""",
        )
        approved = cur.rowcount
        repo.insert_audit_log(
            conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
            "auto_demo_review", "success",
            f"Auto-demo: revoked {revoked}, approved {approved}",
            details={"revoked": revoked, "approved": approved},
        )
    _console().print(f"[green]auto-demo:[/green] revoked {revoked}, approved {approved} (MEDIUM left PENDING)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Reviewer CLI for access certification")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("list", help="List reviews")
    pl.add_argument("--status", choices=["PENDING", "APPROVED", "REVOKED"])
    pl.add_argument("--risk", choices=["LOW", "MEDIUM", "HIGH"])
    pl.add_argument("--user")
    pl.set_defaults(func=cmd_list)
    pd = sub.add_parser("decide", help="Approve/revoke a review")
    pd.add_argument("--review-id", required=True)
    pd.add_argument("--decision", required=True, help="APPROVED|REVOKED")
    pd.add_argument("--comment", default="")
    pd.add_argument("--reviewer", default="")
    pd.set_defaults(func=cmd_decide)
    ps = sub.add_parser("stats", help="Counts by status/risk")
    ps.set_defaults(func=cmd_stats)
    pa = sub.add_parser("audit", help="Tail audit log")
    pa.add_argument("--tail", type=int, default=20)
    pa.set_defaults(func=cmd_audit)
    pm = sub.add_parser("auto-demo", help="Deterministic demo decisions")
    pm.set_defaults(func=cmd_auto_demo)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
