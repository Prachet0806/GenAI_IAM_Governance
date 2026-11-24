import { expect, test, type Page } from "@playwright/test";
import { encode } from "next-auth/jwt";
import AxeBuilder from "@axe-core/playwright";
import { e2eAuthSecret } from "../playwright.config";

const baseURL = "http://127.0.0.1:3100";
const roleGroups: Record<string, string[]> = {
  reviewer: ["reviewer"],
  campaign_admin: ["campaign_admin"],
  remediation_approver: ["remediation_approver"],
  auditor: ["auditor"],
  remediation_operator: ["remediation_operator"],
};

async function expectAccessible(page: Page) {
  const audit = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  const failures = audit.violations.flatMap((item) => item.nodes.map((node) => `${item.id}: ${node.target.join(" ")} (${node.any[0]?.data?.contrastRatio ?? "see axe details"})`));
  expect(failures, failures.join("\n")).toEqual([]);
}

async function authenticate(page: Page, role: keyof typeof roleGroups) {
  let exportCreated = false;
  const token = await encode({
    token: {
      sub: `e2e|${role}`,
      name: `Test ${role}`,
      email: `${role}@example.test`,
      backendAccessToken: "mock-access-token",
      backendAccessTokenExpiresAt: Date.now() + 3_600_000,
    },
    secret: e2eAuthSecret,
    salt: "authjs.session-token",
  });
  await page.context().addCookies([{ name: "authjs.session-token", value: token, url: baseURL }]);
  await page.route("**/api/backend/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/backend\//, "");
    const method = request.method();
    const json = (data: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });

    if (path === "me") return json({ subject: `e2e|${role}`, display_name: `Test ${role}`, email: `${role}@example.test`, roles: roleGroups[role], permissions: [], account_scopes: ["123456789012"], scope_mode: "claim", reviewer_assignment_available: true });
    if (path.startsWith("reviews/queue")) return json({ reviews: [{ review_id: "REV-1", status: "PENDING", name: "Quarterly certification", account_id: "123456789012", principal: "Jordan Lee", grant_name: "BillingReadOnly", risk_level: "HIGH", due_at: null }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path === "reviews/summary") return json({ assigned: 1, pending: 1, approved: 0, revoked: 0, high_risk: 1, overdue: 0 });
    if (path === "reviews/REV-1") return json({ review_id: "REV-1", status: "PENDING", user: "Jordan Lee", entitlement: "BillingReadOnly", risk_level: "HIGH", policy_document: { Version: "2012-10-17", Statement: [{ Sid: "BillingRead", Effect: "Allow", Action: ["billing:GetInvoice"], Resource: "*" }] }, risk_reason: "Billing data access", risk_evidence: { actions: ["billing:GetInvoice"] }, assessment: { risk_severity: "UNKNOWN", assessment_status: "PARTIAL", assessment_confidence: "INSUFFICIENT", reason_codes: ["UNKNOWN_ACTION"], manual_review_required: true, evidence_completeness: { source_coverage: "COMPLETE", document_coverage: "COMPLETE", unassessed_surfaces: [] }, statement_refs: [{ statement_index: 0, sid: "BillingRead", reason_codes: ["UNKNOWN_ACTION"], matched_actions: ["billing:GetInvoice"], policy_sha256: "aabbccdd", attachment_id: "billing-policy", policy_version: "v1" }] }, observed_path: { principal_id: "U-1", principal_name: "Jordan Lee", principal_arn: "arn:aws:iam::123456789012:user/jordan", grant_type: "GROUP_MANAGED", source_id: "G-1", source_name: "FinanceReviewers", attachment_id: "billing-policy", policy_id: "billing-policy", policy_name: "BillingReadOnly", policy_version: "v1", policy_sha256: "aabbccdd", observed_at: "2026-11-01T00:00:00Z", collected_at: "2026-11-01T00:10:00Z", observation_id: "OBS-1" }, risk_rule_version: "rules-v1", snapshot_id: "SNAP-1", grant_id: "GRANT-1", observation_id: "OBS-1", risk_assessment_id: "RISK-1", grant_type: "GROUP_MANAGED", grant_source: "FinanceReviewers", policy_version: "v1", policy_sha256: "aabbccdd", evidence_state: "SNAPSHOT_PINNED", policy_evidence_status: "COMPLETE", missing_policy_reason: null, source_coverage: { complete: true }, source_account_id: "123456789012", source_scope: "IAM_USER_POLICY", snapshot_published_at: "2026-11-01T00:15:00Z", snapshot_current_eligible: true, review_scope: "GRANT_PATH", principal_access_status: "not_evaluated", ai_explanation: { status: "not_available" }, assigned_reviewer_sub: `e2e|${role}`, can_decide: true, can_decide_reason: null, due_at: null, exception_state: "NONE", campaign_state: "OPEN" });
    if (path === "reviews/REV-1/history") return json({ events: method === "POST" ? [{ event_id: "EVENT-1", event_type: "DECISION_RECORDED", decision: "APPROVED", actor_sub: `e2e|${role}`, created_at: new Date().toISOString() }] : [] });
    if (path === "reviews/REV-1/decision" && method === "POST") return json({ status: "APPROVED" });
    if (path === "campaigns" && method === "GET") return json({ campaigns: [], limit: 25, offset: 0, total: 0, has_more: false });
    if (path === "campaigns" && method === "POST") return json({ campaign_id: "CAMP-NEW", name: "Quarterly certification" }, 201);
    if (path === "campaigns/CAMP-NEW") return json({ campaign_id: "CAMP-NEW", name: "Quarterly certification", account_id: "123456789012", source_scope: "IAM_USER_POLICY", snapshot_id: "SNAP-1", state: "OPEN", owner_sub: `e2e|${role}` });
    if (path === "campaigns/CAMP-NEW/progress") return json({ total: 1, pending: 1, completed: 0, approved: 0, revoked: 0, overdue: 0, open_exceptions: 0, high_risk: 1, medium_risk: 0, low_risk: 0, unknown_risk: 0, completion_percent: 0, reviewers: [] });
    if (path === "campaigns/CAMP-NEW/reviewers") return json({ reviewers: [{ reviewer_sub: "e2e|reviewer", assigned_at: "2026-11-02T10:00:00Z", assigned: 1, pending: 1, completed: 0 }] });
    if (path === "campaigns/CAMP-NEW/reviews") return json({ reviews: [{ review_id: "REV-1", status: "PENDING", assigned_reviewer_sub: "e2e|reviewer", due_at: null, exception_state: "NONE", principal: "Jordan Lee", grant_name: "BillingReadOnly", risk_level: "HIGH", account_id: "123456789012" }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path === "campaigns/CAMP-NEW/events") return json({ events: [], limit: 25, offset: 0, total: 0, has_more: false });
    if (path === "reviews/REV-1/assignment" && method === "POST") return json({ status: "assigned" });
    if (path === "snapshots") return json({ snapshots: [{ snapshot_id: "SNAP-0", account_id: "123456789012", source_scope: "IAM_USER_POLICY", published_at: "2026-10-01T00:00:00Z", eligible_for_campaign: false, is_current_publication: false }, { snapshot_id: "SNAP-1", account_id: "123456789012", source_scope: "IAM_USER_POLICY", published_at: "2026-11-01T00:15:00Z", eligible_for_campaign: true, is_current_publication: true }], limit: 25, offset: 0, total: 2, has_more: false });
    if (path === "discovery-attempts") return json({ attempts: [{ attempt_id: "FAILED-1", account_id: "123456789012", source_scope: "IAM_USER_POLICY", started_at: "2026-11-02T00:00:00Z", collection: "FAILED", publication: "NOT_PUBLISHED", grant_count: null, coverage: null, errors: 1, details: { reason: "throttled" } }, { attempt_id: "SNAP-1", account_id: "123456789012", source_scope: "IAM_USER_POLICY", started_at: "2026-11-01T00:00:00Z", collected_at: "2026-11-01T00:10:00Z", collection: "SUCCEEDED", publication: "CURRENT_PUBLISHED", grant_count: 1, missing_document_count: 0, coverage: { complete_for_declared_scope: true } }], limit: 25, offset: 0, total: 2, has_more: false });
    if (path === "snapshots/SNAP-0/compare/SNAP-1") return json({ before: { published_at: "2026-10-01T00:00:00Z", manifest_sha256: "before-hash" }, after: { published_at: "2026-11-01T00:15:00Z", manifest_sha256: "after-hash" }, counts: { added: 0, removed: 0, changed: 1, unchanged: 0 }, changes: [{ kind: "CHANGED", grant_id: "GRANT-1", changed_fields: ["policy_sha256"], before: { principal_name: "Jordan Lee", grant_type: "GROUP_MANAGED", source_name: "FinanceReviewers", policy_name: "BillingReadOnly", policy_version: "v0", policy_sha256: "old-hash", observed_at: "2026-10-01T00:00:00Z" }, after: { principal_name: "Jordan Lee", grant_type: "GROUP_MANAGED", source_name: "FinanceReviewers", policy_name: "BillingReadOnly", policy_version: "v1", policy_sha256: "aabbccdd", observed_at: "2026-11-01T00:00:00Z" } }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path === "snapshots/SNAP-1/readiness") return json({ snapshot_id: "SNAP-1", account_id: "123456789012", source_scope: "IAM_USER_POLICY", published_snapshot_id: "SNAP-1", latest_attempt_status: "COMPLETE", reviewable_grants: 1, eligible_for_campaign: true, blockers: [] });
    if (path === "approvals" && method === "GET") return json({ items: [{ review_id: "REV-1", principal: "Jordan Lee", grant_name: "BillingReadOnly", account_id: "123456789012", status: "REVOKED", risk_level: "HIGH", action_type: "DETACH_USER_POLICY", eligible: true, blockers: [], workflow_state: "AWAITING_APPROVAL" }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path === "approvals/REV-1") return json({ review: { status: "REVOKED", user: "Jordan Lee", reviewer_comment: "No longer needed" }, remediation: { review_id: "REV-1", principal: "Jordan Lee", principal_arn: "arn:aws:iam::123456789012:user/jordan", grant_name: "BillingReadOnly", account_id: "123456789012", source_scope: "IAM_USER_POLICY", snapshot_id: "SNAP-1", grant_id: "GRANT-1", observation_id: "OBS-1", risk_assessment_id: "RISK-1", grant_type: "USER_POLICY", action_type: "DETACH_USER_POLICY", risk_level: "HIGH", reviewer_sub: "e2e|reviewer", reviewer_comment: "No longer needed", status: "REVOKED", eligible: true, blockers: [], execution_state: "NOT_STARTED", history: { approval_events: [], action_events: [], reconciliation_events: [] } }, execution_mode: "DRY_RUN" });
    if (path === "approvals/REV-1/decision" && method === "POST") return json({ status: "APPROVED" });
    if (path.startsWith("audit/events")) return json({ events: [{ event_id: "EVENT-1", campaign_id: "CAMP-1", review_id: "REV-1", event_type: "DECISION_RECORDED", summary: "Approval recorded", actor_sub: "e2e|reviewer", created_at: "2026-11-02T10:00:00Z", details: { previous_value: "PENDING", new_value: "APPROVED" } }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path === "audit/reviews/REV-1") return json({ review_id: "REV-1", campaign_name: "Quarterly certification", account_id: "123456789012", source_scope: "IAM_USER_POLICY", status: "APPROVED", reviewer_sub: "e2e|reviewer", reviewer_comment: "Business need confirmed", review_created_at: "2026-11-01T10:00:00Z", decision_recorded_at: "2026-11-02T10:00:00Z", snapshot_id: "SNAP-1", grant_id: "GRANT-1", observation_id: "OBS-1", risk_assessment_id: "RISK-1", principal_name: "Jordan Lee", policy_name: "BillingReadOnly", policy_document: { Version: "2012-10-17", Statement: [] }, observed_at: "2026-11-01T00:00:00Z", policy_evidence_status: "COMPLETE", missing_policy_reason: null, policy_version: "v1", policy_sha256: "aabbccdd", snapshot_published_at: "2026-11-01T00:15:00Z", risk_level: "HIGH", risk_rule_version: "policy-risk-v6", review_scope: "GRANT_PATH", observed_path: { grant_type: "GROUP_MANAGED", source_name: "FinanceReviewers", source_id: "G-1", attachment_id: "billing-policy" }, assessment: { risk_severity: "UNKNOWN", assessment_status: "PARTIAL", assessment_confidence: "INSUFFICIENT", reason_codes: ["UNKNOWN_ACTION"] }, source_manifest: { sha256: "source-hash", manifest: { kind: "SINGLE_SOURCE" } }, review_manifest: { sha256: "review-hash", manifest: { review_id: "REV-1" } }, evidence_invalidations: [], current_snapshot_eligible: false, decision_history: [{ event_id: "EVENT-1", event_type: "REVIEW_DECISION", decision: "APPROVED", actor_sub: "e2e|reviewer", comment: "Business need confirmed", created_at: "2026-11-02T10:00:00Z" }], remediation_history: {} });
    if (path === "exports" && method === "GET") return json({ exports: exportCreated ? [{ export_id: "EXPORT-1", created_at: "2026-11-02T10:00:00Z", campaign_id: "CAMP-1", record_count: 1, manifest_sha256: "aabbccdd", evidence_sha256: "evidence-hash" }] : [], limit: 25, offset: 0, total: exportCreated ? 1 : 0, has_more: false });
    if (path === "exports" && method === "POST") { exportCreated = true; return json({ export_id: "EXPORT-1", record_count: 1 }, 201); }
    if (path === "exports/EXPORT-1/verify") return json({ valid: true });
    if (path === "operations/health") return json({ api: "ready", database: "ready", status: "ready", worker_heartbeat_available: false });
    if (path === "operations/integrations") return json({ oidc: { configured: true }, aws: { credential_source_configured: true, mock_mode: true, region_configured: true, connectivity: "not_checked" }, genai: { enabled: false }, audit_storage: { s3_bucket_configured: false, kms_key_configured: false }, remediation: { enabled: true, dry_run: true, live_gate_configured: false } });
    if (path.startsWith("operations/jobs")) return json({ jobs: [{ job_id: "JOB-1", job_type: "DISCOVERY", status: "COMPLETE", started_at: "2026-11-02T10:00:00Z", account_id: "123456789012", source: "mock" }], limit: 25, offset: 0, total: 1, has_more: false });
    if (path.startsWith("operations/audit")) return json({ events: [{ event_id: "OPS-1", created_at: "2026-11-02T10:00:00Z", action: "discovery_complete", entity_type: "campaign", status: "success", details_redacted: true }], limit: 25, offset: 0, next_offset: null });
    if (path === "reviews/REV-1/remediation/reconciliation" && method === "POST") return json({ request_id: "RECHECK-1" }, 202);
    return json({ error: { message: `Unmocked API request: ${method} ${path}` } }, 404);
  });
}

test("reviewer completes an evidence based decision journey", async ({ page }) => {
  await authenticate(page, "reviewer");
  await page.goto("/reviews");
  await expect(page.getByRole("heading", { name: "My review queue" })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("link", { name: /Review/ }).click();
  await expect(page.getByText("BillingReadOnly").first()).toBeVisible();
  await expect(page.getByText(/one observed grant path/i)).toBeVisible();
  await expect(page.getByRole("list", { name: "Observed grant path" })).toContainText("FinanceReviewers");
  await page.getByText(/Inspect frozen policy statements/).click();
  await expect(page.getByText(/Rule finding for this statement/)).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Approve grant path" }).click();
  await expect(page.getByRole("dialog")).toContainText("Jordan Lee");
  await page.getByRole("button", { name: "Record approval" }).click();
  await expect(page.getByRole("status").filter({ hasText: "decision recorded" })).toBeVisible();
});

test("campaign administrator checks a snapshot and creates a campaign", async ({ page }) => {
  await authenticate(page, "campaign_admin");
  await page.goto("/campaigns");
  await expect(page.getByRole("heading", { name: "Discovery attempts" })).toBeVisible();
  await expect(page.getByText("throttled")).toBeVisible();
  await page.getByLabel("Earlier snapshot ID").fill("SNAP-0");
  await page.getByLabel("Later snapshot ID").fill("SNAP-1");
  await expect(page.getByText("Observed grant-path comparison only.")).toBeVisible();
  await expect(page.getByText("before-hash")).toBeVisible();
  await page.getByRole("link", { name: "Create campaign" }).click();
  await page.getByLabel("Published snapshot").selectOption("SNAP-1");
  await expect(page.getByText("Evidence is ready")).toBeVisible();
  await page.getByLabel("Campaign name").fill("Quarterly certification");
  await page.getByRole("button", { name: "Create campaign" }).click();
  await expect(page).toHaveURL(/campaigns\/CAMP-NEW/);
  await expect(page.getByRole("heading", { name: "Quarterly certification" })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("checkbox", { name: "Select review REV-1" }).check();
  await page.getByLabel("Assign selected pending reviews to").fill("e2e|reviewer2");
  await page.getByRole("button", { name: "Assign selected (1)" }).click();
  await expect(page.getByRole("dialog")).toContainText("Each review is updated separately");
  await page.getByRole("button", { name: "Confirm change" }).click();
  await expect(page.getByRole("status")).toContainText("1 review assigned");
});

test("remediation approver inspects blockers and records independent approval", async ({ page }) => {
  await authenticate(page, "remediation_approver");
  await page.goto("/remediation");
  await expectAccessible(page);
  await page.getByRole("link", { name: "Inspect request" }).click();
  await expect(page.getByRole("heading", { name: "BillingReadOnly" })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel(/Your independent decision/).selectOption("APPROVED");
  await page.getByLabel(/Reason/).fill("Independent review completed");
  await page.getByRole("button", { name: "Review approved decision" }).click();
  await expect(page.getByRole("dialog")).toContainText("Jordan Lee");
  await page.getByRole("button", { name: "Record decision" }).click();
  await expect(page.getByRole("status")).toContainText("Independent approved decision recorded");
});

test("auditor investigates an event and requests a verifiable export", async ({ page }) => {
  await authenticate(page, "auditor");
  await page.goto("/audit");
  await expect(page.getByText("Approval recorded")).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("link", { name: "Reconstruct historical review" }).click();
  await expect(page.getByText("Business need confirmed").first()).toBeVisible();
  await expect(page.getByText("source-hash")).toBeVisible();
  await page.getByRole("link", { name: "← Audit and exports" }).click();
  await page.getByLabel("Event type").fill("DECISION_RECORDED");
  await page.getByRole("button", { name: "Generate export" }).click();
  await expect(page.getByRole("status")).toContainText("Export created");
  await page.getByRole("button", { name: "Verify artifacts" }).click();
  await expect(page.getByRole("status")).toContainText("verified");
});

test("operator requests a safe exact path reconciliation", async ({ page }) => {
  await authenticate(page, "remediation_operator");
  await page.goto("/operations");
  await expect(page.getByText(/Worker heartbeat is unavailable/i)).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel("Review ID").fill("REV-1");
  await page.getByLabel("Reason").fill("Confirm the observed grant is absent");
  await page.getByRole("button", { name: "Review recheck request" }).click();
  await expect(page.getByRole("dialog")).toContainText("does not perform a destructive action");
  await page.getByRole("button", { name: "Request recheck" }).click();
  await expect(page.getByRole("status")).toContainText("RECHECK-1");
});
