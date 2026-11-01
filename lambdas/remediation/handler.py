"""Path-specific IAM user remediation with durable intent and verification."""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

import boto3

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common import config, evidence, logger, repo
from common.db import db
from lambdas.identity_discovery.handler import _get_policy_document


class PreflightRejected(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _should_detach(
    role_name: str, role_arn: str = "", allowlist: set | None = None,
    denylist: set | None = None,
):
    """Deny exact names/ARNs or explicit *substring* patterns; allow exact only."""
    allow = {_norm(a) for a in (allowlist if allowlist is not None else config.get_allowlist())}
    deny = {_norm(d) for d in config.MANDATORY_DENYLIST}
    deny.update(_norm(d) for d in (denylist if denylist is not None else config.get_denylist()))
    name, arn = _norm(role_name), _norm(role_arn)
    for entry in deny:
        if not entry:
            continue
        if entry.startswith("*") and entry.endswith("*") and len(entry) > 2:
            needle = entry.strip("*")
            if needle and (needle in name or needle in arn):
                return False, f"Denied by denylist pattern ({entry})"
        elif name == entry or arn == entry:
            return False, f"Denied by denylist ({entry})"
    if allow and not (name in allow or arn in allow):
        return False, "Skipped: not in remediation allowlist"
    return True, "Allowed"


def _get_iam_client():
    from botocore.config import Config as BotoConfig

    client_config = BotoConfig(
        connect_timeout=5, read_timeout=20,
        retries={"mode": "standard", "max_attempts": 3},
    )
    profile = config.get_aws_profile()
    if profile:
        return boto3.Session(
            profile_name=profile, region_name=config.get_aws_region()
        ).client("iam", config=client_config)
    return boto3.client(
        "iam", region_name=config.get_aws_region(), config=client_config
    )


def _is_policy_attached(iam, user_name: str, policy_arn: str) -> bool:
    return any(
        item.get("PolicyArn") == policy_arn
        for page in iam.get_paginator("list_attached_user_policies").paginate(
            UserName=user_name
        )
        for item in page.get("AttachedPolicies", [])
    )


def _is_inline_present(iam, user_name: str, policy_name: str) -> bool:
    return any(
        name == policy_name
        for page in iam.get_paginator("list_user_policies").paginate(
            UserName=user_name
        )
        for name in page.get("PolicyNames", [])
    )


def _read_live_path(iam, binding: dict) -> dict:
    """Read the exact principal and attachment; retain hashes, not policy text."""
    user_name = binding["principal_name"]
    live_user = iam.get_user(UserName=user_name).get("User", {})
    if (live_user.get("UserId"), live_user.get("Arn")) != (
        binding["principal_id"], binding["principal_arn"]
    ):
        raise PreflightRejected("principal_identity_changed")
    grant_type = binding["grant_type"]
    attachment = binding["attachment_id"]
    if grant_type == "DIRECT_MANAGED":
        if attachment != binding["policy_id"] or not attachment.startswith("arn:"):
            raise PreflightRejected("managed_attachment_identity_invalid")
        present = _is_policy_attached(iam, user_name, attachment)
        if present:
            document, version = _get_policy_document(iam, attachment)
        else:
            document, version = None, None
    elif grant_type == "DIRECT_INLINE":
        present = _is_inline_present(iam, user_name, attachment)
        if present:
            document = iam.get_user_policy(
                UserName=user_name, PolicyName=attachment
            ).get("PolicyDocument")
            if isinstance(document, str):
                document = json.loads(unquote(document))
            if not isinstance(document, dict):
                raise PreflightRejected("inline_document_unreadable")
        else:
            document = None
        version = None
    else:
        raise PreflightRejected("unsupported_grant_type")
    return {
        "principal_id": live_user["UserId"],
        "principal_arn": live_user["Arn"],
        "attachment_id": attachment,
        "attachment_present": present,
        "policy_sha256": (
            hashlib.sha256(evidence.canonical_json(document).encode("utf-8")).hexdigest()
            if document is not None else None
        ),
        "policy_version": version,
    }


def _check_live_observation(binding: dict, observed: dict):
    if not observed["attachment_present"]:
        return
    if observed["policy_sha256"] != binding["policy_sha256"]:
        raise PreflightRejected("policy_document_changed")
    if (binding["grant_type"] == "DIRECT_MANAGED"
            and observed["policy_version"] != binding["policy_version"]):
        raise PreflightRejected("managed_policy_version_changed")


def _eligible_path(conn, review_id: str, binding: dict, account_id: str) -> bool:
    if (binding["grant_type"] not in repo.REMEDIATION_ACTIONS
            or binding["evidence_status"] != "COMPLETE"
            or binding["account_id"] != account_id):
        return False
    snapshot = repo.eligible_published_snapshot(
        conn, binding["account_id"], binding["source_scope"], require_aws=True
    )
    return bool(
        snapshot and snapshot["snapshot_id"] == binding["snapshot_id"]
        and repo.is_current_grant_for_review(conn, review_id)
        and repo.is_remediation_approved(conn, review_id, binding["snapshot_id"])
    )


def _event(conn, attempt_id, review_id, approval_event_id, kind, binding,
           claim_token, fencing_token, actor_id, data):
    return repo.record_remediation_action_event(
        conn, attempt_id=attempt_id, review_id=review_id,
        approval_event_id=approval_event_id, event_type=kind,
        action_type=repo.REMEDIATION_ACTIONS[binding["grant_type"]],
        actor_id=actor_id, binding=binding, claim_token=claim_token,
        fencing_token=fencing_token,
        evidence_data=data,
    )


def _renew(conn, review_id, claim_token, fencing_token) -> bool:
    now = datetime.now(timezone.utc)
    return repo.renew_remediation_claim(
        conn, review_id, claim_token, fencing_token, now.isoformat(),
        (now + timedelta(minutes=5)).isoformat(),
    )


def _finish(conn, review_id, claim_token, fencing_token, *, remediated=False):
    if remediated and not repo.mark_remediated_if_claim_owned(
        conn, review_id, claim_token, fencing_token, _now()
    ):
        raise RuntimeError("Remediation claim no longer owns the review")
    repo.release_remediation_claim(conn, review_id, claim_token, fencing_token)
    conn.commit()


def _reconcile(conn, iam, review_id, binding, pending, claim_token,
               fencing_token, actor_id):
    """After an ambiguous AWS call, observe the path without repeating it."""
    attempt_id, approval_event_id, _action_type, _old_epoch = pending
    repo.lock_inventory_remediation(conn)
    if not _renew(conn, review_id, claim_token, fencing_token):
        return "skipped"
    try:
        observed = _read_live_path(iam, binding)
    except Exception as exc:
        observed = {"read_error_type": type(exc).__name__}
    if observed.get("attachment_present") is False:
        _event(conn, attempt_id, review_id, approval_event_id,
               "ACTION_VERIFIED", binding, claim_token, fencing_token, actor_id,
               {"postflight": observed, "recovered_after_uncertain_action": True,
                "principal_access_status": "not_evaluated"})
        _finish(conn, review_id, claim_token, fencing_token, remediated=True)
        return "remediated"
    _event(conn, attempt_id, review_id, approval_event_id,
           "RECONCILIATION_REQUIRED", binding, claim_token, fencing_token, actor_id,
           {"postflight": observed, "reason": "action_outcome_uncertain"})
    _finish(conn, review_id, claim_token, fencing_token)
    return "reconciliation_required"


def _process_review(review_id: str, account_id: str, actor_id: str,
                    allowlist: set) -> str:
    claim_token = None
    fencing_token = None
    intent_recorded = False
    with db.get_connection() as conn:
        try:
            binding = repo.review_evidence_binding(conn, review_id)
            if not binding or binding["grant_type"] not in repo.REMEDIATION_ACTIONS:
                return "skipped"
            pending = repo.pending_remediation_intent(conn, review_id)
            if repo.remediation_reconciliation_required(conn, review_id):
                return "reconciliation_required"
            if not pending:
                allowed, _ = _should_detach(
                    binding["policy_name"], binding["policy_id"], allowlist=allowlist
                )
                if not allowed or not _eligible_path(conn, review_id, binding, account_id):
                    return "skipped"
            claim_token = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            fencing_token = repo.claim_remediation(
                conn, review_id, claim_token, now.isoformat(),
                (now + timedelta(minutes=5)).isoformat(),
            )
            if fencing_token is None:
                return "skipped"
            conn.commit()
            approval_event_id = (
                pending[1] if pending else
                repo.current_remediation_approval_event(conn, review_id)
            )
            if not approval_event_id:
                _finish(conn, review_id, claim_token, fencing_token)
                return "skipped"
            iam = _get_iam_client()
            if pending:
                return _reconcile(
                    conn, iam, review_id, binding, pending, claim_token,
                    fencing_token, actor_id,
                )

            attempt_id = str(uuid.uuid4())
            first = _read_live_path(iam, binding)
            _check_live_observation(binding, first)
            repo.lock_inventory_remediation(conn)
            if (not _renew(conn, review_id, claim_token, fencing_token)
                    or not _eligible_path(conn, review_id, binding, account_id)
                    or repo.current_remediation_approval_event(conn, review_id)
                    != approval_event_id):
                _finish(conn, review_id, claim_token, fencing_token)
                return "skipped"
            if not first["attachment_present"]:
                final = _read_live_path(iam, binding)
                if final["attachment_present"]:
                    _event(conn, attempt_id, review_id, approval_event_id,
                           "PREFLIGHT_REJECTED", binding, claim_token, fencing_token, actor_id,
                           {"reason": "attachment_changed_during_preflight",
                            "preflight": first, "final": final})
                    _finish(conn, review_id, claim_token, fencing_token)
                    return "skipped"
                _event(conn, attempt_id, review_id, approval_event_id,
                       "ALREADY_ABSENT", binding, claim_token, fencing_token, actor_id,
                       {"preflight": first, "final": final,
                        "principal_access_status": "not_evaluated"})
                _finish(conn, review_id, claim_token, fencing_token, remediated=True)
                return "remediated"

            _event(conn, attempt_id, review_id, approval_event_id,
                   "PREFLIGHT_PASSED", binding, claim_token, fencing_token, actor_id,
                   {"preflight": first})
            _event(conn, attempt_id, review_id, approval_event_id,
                   "ACTION_REQUESTED", binding, claim_token, fencing_token, actor_id,
                   {"action": repo.REMEDIATION_ACTIONS[binding["grant_type"]],
                    "attachment_id": binding["attachment_id"]})
            conn.commit()
            intent_recorded = True

            # The mutex is held through the final AWS read, mutation, and
            # verification. The committed intent survives a later DB failure.
            repo.lock_inventory_remediation(conn)
            if (not _renew(conn, review_id, claim_token, fencing_token)
                    or not _eligible_path(conn, review_id, binding, account_id)
                    or repo.current_remediation_approval_event(conn, review_id)
                    != approval_event_id):
                _event(conn, attempt_id, review_id, approval_event_id,
                       "ABORTED", binding, claim_token, fencing_token, actor_id,
                       {"reason": "final_eligibility_or_lease_failed"})
                _finish(conn, review_id, claim_token, fencing_token)
                return "skipped"
            final = _read_live_path(iam, binding)
            if not final["attachment_present"]:
                _event(conn, attempt_id, review_id, approval_event_id,
                       "ACTION_VERIFIED", binding, claim_token, fencing_token, actor_id,
                       {"final_preflight": final, "mutation_performed": False,
                        "principal_access_status": "not_evaluated"})
                _finish(conn, review_id, claim_token, fencing_token, remediated=True)
                return "remediated"
            try:
                _check_live_observation(binding, final)
            except PreflightRejected as exc:
                _event(conn, attempt_id, review_id, approval_event_id,
                       "ABORTED", binding, claim_token, fencing_token, actor_id,
                       {"reason": str(exc), "final_preflight": final})
                _finish(conn, review_id, claim_token, fencing_token)
                return "skipped"
            if binding["grant_type"] == "DIRECT_MANAGED":
                iam.detach_user_policy(
                    UserName=binding["principal_name"],
                    PolicyArn=binding["attachment_id"],
                )
            else:
                iam.delete_user_policy(
                    UserName=binding["principal_name"],
                    PolicyName=binding["attachment_id"],
                )
            verified = _read_live_path(iam, binding)
            if verified["attachment_present"]:
                _event(conn, attempt_id, review_id, approval_event_id,
                       "RECONCILIATION_REQUIRED", binding, claim_token, fencing_token, actor_id,
                       {"final_preflight": final, "postflight": verified,
                        "reason": "attachment_remained_after_action"})
                _finish(conn, review_id, claim_token, fencing_token)
                return "reconciliation_required"
            _event(conn, attempt_id, review_id, approval_event_id,
                   "ACTION_VERIFIED", binding, claim_token, fencing_token, actor_id,
                   {"final_preflight": final, "postflight": verified,
                    "mutation_performed": True,
                    "principal_access_status": "not_evaluated"})
            _finish(conn, review_id, claim_token, fencing_token, remediated=True)
            return "remediated"
        except Exception as exc:
            conn.rollback()
            if claim_token and fencing_token is not None:
                try:
                    if not intent_recorded and not pending and binding:
                        _event(conn, locals().get("attempt_id", str(uuid.uuid4())),
                               review_id, locals().get("approval_event_id"),
                               "PREFLIGHT_REJECTED", binding, claim_token, fencing_token,
                               actor_id, {"error_type": type(exc).__name__,
                                          "reason": str(exc) if isinstance(
                                              exc, PreflightRejected
                                          ) else "preflight_unavailable"})
                    repo.release_remediation_claim(
                        conn, review_id, claim_token, fencing_token
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
            logger.log(
                "remediate_access", "error", "Remediation attempt failed",
                level="ERROR", entity_type="access_review", entity_id=review_id,
                details={"error_type": type(exc).__name__,
                         "action_intent_recorded": intent_recorded},
            )
            return "failed"


def remediate_access(event, context):
    dry_run = config.is_dry_run()
    enabled = config.is_remediation_enabled()
    with db.get_connection() as conn:
        revocations = repo.list_revocations(conn)
    if dry_run or not enabled:
        preview = [
            {"review_id": review_id, "policy": policy_name,
             "policy_id": policy_id}
            for review_id, _user_name, policy_name, policy_id in revocations[:10]
        ]
        logger.log(
            "remediate_access", "plan", "Preflight only; no IAM mutation",
            details={"total_pending": len(revocations), "preview": preview},
        )
        return {
            "status": "success", "remediated": 0, "skipped": len(revocations),
            "failed": 0, "reconciliation_required": 0, "dry_run": True,
            "total_pending": len(revocations), "preview": preview,
        }
    if os.getenv("APP_ENV", "development").lower() == "production":
        reason = "production_live_remediation_disabled"
    elif os.getenv("APP_ENV", "development").lower() != "staging":
        reason = "staging_environment_required"
    elif config.is_mock_iam():
        reason = "mock_mode"
    elif not config.is_live_remediation_explicitly_allowed() or not config.get_allowlist():
        reason = "missing_live_safety_configuration"
    elif not config.get_staging_remediation_acceptance_id():
        reason = "staging_acceptance_required"
    else:
        reason = None
    if reason:
        return {"status": "blocked", "reason": reason, "remediated": 0,
                "skipped": 0, "failed": 0, "reconciliation_required": 0,
                "dry_run": False}
    try:
        account_id = config.get_aws_account_id()
    except ValueError:
        return {"status": "blocked", "reason": "aws_account_id_required",
                "remediated": 0, "skipped": 0, "failed": 0,
                "reconciliation_required": 0, "dry_run": False}
    actor_id = getattr(context, "aws_request_id", None) or os.getenv(
        "REMEDIATION_WORKER_ID", "remediation-worker"
    )
    counts = {"remediated": 0, "skipped": 0, "failed": 0,
              "reconciliation_required": 0}
    for review_id, *_ in revocations:
        outcome = _process_review(
            review_id, account_id, actor_id, config.get_allowlist()
        )
        counts[outcome] += 1
    return {"status": "success" if not counts["failed"] else "partial_failure",
            **counts, "dry_run": False}


if __name__ == "__main__":
    print(remediate_access(None, None))
