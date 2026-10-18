"""Minimal OIDC-protected API for campaign reviewer assignment and decisions.

Run behind a TLS-terminating gateway with restricted network access:
    uvicorn api.review_service:app --host 127.0.0.1 --port 8080
"""
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from common import auth, repo
from common.db import db

app = FastAPI(title="IAM Access Review API", docs_url=None, redoc_url=None, openapi_url=None)
bearer = HTTPBearer(auto_error=False)


class DecisionRequest(BaseModel):
    decision: Literal["APPROVED", "REVOKED"]
    comment: str = Field(default="", max_length=4000)


class ReviewerAssignmentRequest(BaseModel):
    reviewer_sub: str = Field(min_length=1, max_length=256)


def current_reviewer(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = auth.verify_access_token(credentials.credentials)
    except auth.AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid access token", headers={"WWW-Authenticate": "Bearer"})
    return claims


def require_reviewer_group(claims: dict):
    try:
        auth.require_group(claims, os.getenv("REVIEWER_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(status_code=403, detail="Reviewer group membership required")


def require_campaign_assignment(conn, campaign_id: str, reviewer_sub: str):
    if not repo.is_campaign_reviewer(conn, campaign_id, reviewer_sub):
        raise HTTPException(status_code=403, detail="Reviewer is not assigned to this campaign")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/reviews/{review_id}")
def get_review(review_id: str, claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    with db.get_connection() as conn:
        row = repo.fetch_review_ai_context(conn, review_id)
        if not row:
            raise HTTPException(status_code=404, detail="Review not found")
        require_campaign_assignment(conn, _review_campaign_id(conn, review_id), claims["sub"])
        return {
            "review_id": row[0], "status": row[1], "user": row[4], "entitlement": row[5],
            "risk_level": row[6], "policy_document": json.loads(row[7]) if row[7] else None,
            "risk_reason": row[8], "risk_evidence": json.loads(row[9]) if row[9] else None,
            "risk_rule_version": row[10],
        }


def _review_campaign_id(conn, review_id: str) -> str:
    review = repo.fetch_review_for_decision(conn, review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    return review[1]


@app.post("/reviews/{review_id}/decision")
def decide_review(review_id: str, request: DecisionRequest, claims: dict = Depends(current_reviewer)):
    require_reviewer_group(claims)
    if request.decision == "REVOKED" and not request.comment.strip():
        raise HTTPException(status_code=422, detail="A revocation requires a comment")
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        require_campaign_assignment(conn, review[1], claims["sub"])
        if review[2] != "PENDING":
            raise HTTPException(status_code=409, detail="Review has already been decided")
        now = datetime.now(timezone.utc)
        cur = conn.cursor()
        db.execute(cur, """UPDATE access_reviews SET status=?, reviewer_comment=?, reviewed_at=?, reviewer_sub=?
            WHERE review_id=? AND status='PENDING'""",
            (request.decision, request.comment.strip(), now.isoformat(), claims["sub"], review_id))
        if cur.rowcount != 1:
            raise HTTPException(status_code=409, detail="Review decision raced with another update")
        repo.insert_audit_log(conn, str(uuid.uuid4()), now, "INFO", "review_decision", request.decision,
                              "Authenticated campaign reviewer recorded a decision",
                              entity_type="access_review", entity_id=review_id,
                              details={"reviewer_sub": claims["sub"], "campaign_id": review[1],
                                       "decision": request.decision, "comment": request.comment.strip()})
    return {"review_id": review_id, "status": request.decision}


@app.post("/campaigns/{campaign_id}/reviewers", status_code=201)
def assign_reviewer(campaign_id: str, request: ReviewerAssignmentRequest,
                    claims: dict = Depends(current_reviewer)):
    try:
        auth.require_group(claims, os.getenv("CAMPAIGN_ADMIN_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(status_code=403, detail="Campaign administrator group membership required")
    with db.get_connection() as conn:
        if not repo.campaign_exists(conn, campaign_id):
            raise HTTPException(status_code=404, detail="Campaign not found")
        created = repo.assign_campaign_reviewer(conn, campaign_id, request.reviewer_sub.strip(), claims["sub"])
        if created:
            repo.insert_audit_log(conn, str(uuid.uuid4()), datetime.now(timezone.utc), "INFO",
                                  "campaign_reviewer_assignment", "success",
                                  "Campaign reviewer assigned", entity_type="campaign", entity_id=campaign_id,
                                  details={"reviewer_sub": request.reviewer_sub.strip(), "assigned_by": claims["sub"]})
    return {"campaign_id": campaign_id, "reviewer_sub": request.reviewer_sub.strip(),
            "status": "assigned" if created else "already_assigned"}


@app.post("/reviews/{review_id}/remediation-approval")
def approve_remediation(review_id: str, response: Response,
                        claims: dict = Depends(current_reviewer)):
    try:
        auth.require_group(claims, os.getenv("REMEDIATION_APPROVER_GROUP", ""))
    except auth.AuthorizationError:
        raise HTTPException(status_code=403, detail="Remediation approver group membership required")
    with db.get_connection() as conn:
        review = repo.fetch_review_for_decision(conn, review_id)
        if not review:
            raise HTTPException(status_code=404, detail="Review not found")
        if review[2] != "REVOKED":
            raise HTTPException(status_code=409, detail="Only revoked reviews can be approved for remediation")
        if not review[5]:
            raise HTTPException(status_code=409, detail="Review does not have a verified reviewer subject")
        if review[5] == claims["sub"]:
            raise HTTPException(status_code=403, detail="The reviewer cannot approve their own remediation")
        discovery = repo.latest_discovery_run(conn)
        if (not discovery or discovery[2] != "COMPLETE"
                or not str(discovery[3] or "").startswith("AWS:iam-users-direct-and-group-managed-and-inline-policies-v2")):
            raise HTTPException(status_code=409, detail="A complete supported AWS discovery run is required")
        previous = repo.get_remediation_approval(conn, review_id)
        now = datetime.now(timezone.utc)
        created = repo.record_remediation_approval(conn, str(uuid.uuid4()), review_id,
                                                   claims["sub"], now.isoformat(), discovery[0])
        if not created:
            raise HTTPException(status_code=409, detail="A remediation approval already exists for this discovery run")
        renewed = previous is not None
        response.status_code = 200 if renewed else 201
        status = "renewed" if renewed else "approved"
        repo.insert_audit_log(conn, str(uuid.uuid4()), now, "INFO", "remediation_approval", status,
                              "Independent authenticated approver authorized or renewed remediation",
                              entity_type="access_review", entity_id=review_id,
                              details={"approver_sub": claims["sub"], "reviewer_sub": review[5],
                                       "discovery_run_id": discovery[0], "renewed": renewed})
    return {"review_id": review_id, "status": status, "discovery_run_id": discovery[0]}
