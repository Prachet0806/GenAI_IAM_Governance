import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewWorkspace } from "./review-workspace";
import type { ReviewDetail } from "@/lib/api/types";

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }));
vi.mock("@/lib/api/client", () => ({ apiFetch }));

const review: ReviewDetail = {
  review_id: "review-1", status: "PENDING", user: "Jordan Lee", entitlement: "BillingReadOnly",
  risk_level: "HIGH", policy_document: { Version: "2012-10-17", Statement: [] },
  risk_reason: "Read access includes billing data", risk_evidence: { actions: ["billing:Get*"] },
  assessment: null, source_manifest_sha256: null, review_manifest_sha256: null,
  evidence_invalidations: [],
  risk_rule_version: "rules-v3", snapshot_id: "snapshot-1", grant_id: "grant-1",
  observation_id: "observation-1", risk_assessment_id: "assessment-1", grant_type: "USER_POLICY",
  grant_source: "Inline policy", policy_version: "v4", policy_sha256: "abc123",
  evidence_state: "snapshot_pinned", policy_evidence_status: "COMPLETE", missing_policy_reason: null,
  source_coverage: { complete: true }, source_account_id: "123456789012", source_scope: "IAM_USER_POLICY",
  snapshot_published_at: "2026-01-01T00:00:00Z", snapshot_current_eligible: true,
  review_scope: "GRANT_PATH", principal_access_status: "not_evaluated",
  ai_explanation: { status: "not_available", summary: null }, assigned_reviewer_sub: "oidc|reviewer",
  review_qa_enabled: false,
  can_decide: true, can_decide_reason: null,
  due_at: null, exception_state: "NONE", campaign_state: "OPEN",
};

function renderReview() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ReviewWorkspace reviewId="review-1" /></QueryClientProvider>);
}

describe("ReviewWorkspace", () => {
  afterEach(() => { cleanup(); vi.restoreAllMocks(); });
  beforeEach(() => {
    apiFetch.mockReset();
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve(review);
      return Promise.resolve({ status: "REVOKED" });
    });
  });

  it("keeps observed grant evidence distinct from effective access and records a commented revocation", async () => {
    renderReview();
    expect(await screen.findByText("BillingReadOnly")).toBeInTheDocument();
    expect(screen.getByText("Not evaluated")).toBeInTheDocument();
    expect(screen.getByText(/one observed grant path/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke grant path" })).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/Reviewer comment/), { target: { value: "No longer required" } });
    fireEvent.click(screen.getByRole("button", { name: "Revoke grant path" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("Jordan Lee");
    expect(screen.getByRole("dialog")).toHaveTextContent("BillingReadOnly");
    expect(apiFetch).not.toHaveBeenCalledWith("reviews/review-1/decision", expect.anything());
    fireEvent.click(screen.getByRole("button", { name: "Record revocation" }));

    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith("reviews/review-1/decision", expect.objectContaining({
      method: "POST", body: JSON.stringify({ decision: "REVOKED", comment: "No longer required" }),
    })));
  });

  it("cancels a decision without sending it to the API", async () => {
    renderReview();
    fireEvent.click(await screen.findByRole("button", { name: "Approve grant path" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("This exact review decision will be recorded");
    fireEvent.click(screen.getByRole("button", { name: "Go back" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(apiFetch).not.toHaveBeenCalledWith("reviews/review-1/decision", expect.anything());
  });

  it("blocks decisions when the bound snapshot is no longer eligible", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      return Promise.resolve({ ...review, snapshot_current_eligible: false });
    });
    renderReview();
    expect(await screen.findByRole("alert")).toHaveTextContent("Evidence is no longer current");
    expect(screen.getByRole("button", { name: "Approve grant path" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke grant path" })).toBeDisabled();
  });

  it("lets a campaign-pool reviewer act when the review has no individual assignee", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path === "me") return Promise.resolve({ subject: "oidc|reviewer", roles: ["reviewer"] });
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({ ...review, assigned_reviewer_sub: null });
      return Promise.resolve({ status: "APPROVED" });
    });
    renderReview();
    expect(await screen.findByRole("button", { name: "Approve grant path" })).toBeEnabled();
  });

  it("uses API eligibility and explains a read-only review", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({
        ...review, can_decide: false, can_decide_reason: "CAMPAIGN_MEMBERSHIP_REQUIRED",
      });
      return Promise.resolve({});
    });
    renderReview();
    expect(await screen.findByText(/not assigned to this campaign's reviewer pool/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve grant path" })).not.toBeInTheDocument();
  });

  it("shows uncertainty instead of the legacy HIGH routing label", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({
        ...review,
        assessment: {
          schema_version: "risk-assessment-v1",
          risk_severity: "UNKNOWN",
          assessment_status: "PARTIAL",
          assessment_confidence: "INSUFFICIENT",
          manual_review_required: true,
          reason_codes: ["POLICY_DOCUMENT_MISSING"],
          evidence_completeness: {
            collection_status: "COMPLETE", source_coverage: "COMPLETE",
            unassessed_surfaces: [],
            document_coverage: "PARTIAL", interpretability: "PARTIAL",
            missing_evidence_count: 1, unsupported_constructs: [],
            reason_codes: ["REFERENCED_POLICY_DOCUMENT_MISSING"],
          },
        },
      });
      return Promise.resolve({});
    });
    renderReview();
    expect(await screen.findByText("Assessment incomplete", { selector: ".badge" })).toBeInTheDocument();
    expect(screen.getByText(/Some policy evidence or constructs could not be evaluated/)).toBeInTheDocument();
    expect(screen.queryByText("High risk")).not.toBeInTheDocument();
  });

  it("shows an invalidation without replacing the pinned review", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({
        ...review,
        snapshot_current_eligible: false,
        evidence_invalidations: [{
          invalidation_id: "invalid-1", manifest_sha256: "hash-1",
          reason_code: "EVIDENCE_DEFECT", detail: "Source evidence needs correction",
          actor_sub: "admin", recorded_at: "2026-01-02T00:00:00Z",
        }],
      });
      return Promise.resolve({});
    });
    renderReview();
    expect(await screen.findByText(/Source evidence needs correction/)).toBeInTheDocument();
    expect(screen.getByText("Pinned evidence was invalidated.")).toBeInTheDocument();
    expect(screen.getByText("snapshot-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve grant path" })).toBeDisabled();
  });

  it("traces a group grant to its pinned attachment and rule statement", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({
        ...review,
        observed_path: {
          principal_id: "U1", principal_name: "Jordan Lee",
          principal_arn: "arn:aws:iam::123456789012:user/jordan",
          grant_type: "GROUP_MANAGED", source_id: "G1", source_name: "FinanceReviewers",
          attachment_id: "arn:aws:iam::123456789012:policy/BillingReadOnly",
          policy_id: "billing-policy", policy_name: "BillingReadOnly",
          policy_version: "v4", policy_sha256: "abc123",
          observed_at: "2026-01-01T00:00:00Z", collected_at: "2026-01-01T00:05:00Z",
          observation_id: "observation-1",
        },
        assessment: {
          schema_version: "risk-assessment-v1", risk_severity: "HIGH",
          assessment_status: "SUPPORTED", assessment_confidence: "HIGH",
          manual_review_required: true, reason_codes: ["SENSITIVE_ACTION"],
          statement_refs: [{ statement_index: 0, sid: "BillingRead", effect: "Allow",
            matched_actions: ["iam:PassRole"], reason_codes: ["SENSITIVE_ACTION"],
            policy_sha256: "abc123", attachment_id: "billing-policy", policy_version: "v4" }],
          evidence_completeness: { collection_status: "COMPLETE", source_coverage: "COMPLETE",
            unassessed_surfaces: [], document_coverage: "COMPLETE", interpretability: "SUPPORTED",
            missing_evidence_count: 0, unsupported_constructs: [], reason_codes: [] },
        },
        policy_document: { Version: "2012-10-17", Statement: [
          { Sid: "BillingRead", Effect: "Allow", Action: "iam:PassRole", Resource: "*" },
        ] },
      });
      return Promise.resolve({});
    });
    renderReview();
    const path = await screen.findByRole("list", { name: "Observed grant path" });
    expect(path).toHaveTextContent("FinanceReviewers");
    expect(path).toHaveTextContent("arn:aws:iam::123456789012:policy/BillingReadOnly");
    fireEvent.click(screen.getByText(/Inspect frozen policy statements/));
    expect(screen.getByText(/Rule finding for this statement/)).toBeInTheDocument();
    expect(screen.getByText(/Exact frozen statement JSON/)).toBeInTheDocument();
  });

  it("renders an older review response without the new evidence annotations", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") {
        const { assessment, source_manifest_sha256, review_manifest_sha256, evidence_invalidations, ...olderReview } = review;
        void assessment; void source_manifest_sha256; void review_manifest_sha256; void evidence_invalidations;
        return Promise.resolve(olderReview);
      }
      return Promise.resolve({});
    });
    renderReview();
    expect(await screen.findByText("BillingReadOnly")).toBeInTheDocument();
    expect(screen.getByText("High legacy triage", { selector: ".badge" })).toBeInTheDocument();
    expect(screen.queryByText("Pinned evidence was invalidated.")).not.toBeInTheDocument();
  });

  it("shows the gated pinned question set and its citations", async () => {
    apiFetch.mockImplementation((path: string) => {
      if (path.startsWith("reviews/review-1/history")) return Promise.resolve({ events: [] });
      if (path === "reviews/review-1") return Promise.resolve({ ...review, review_qa_enabled: true });
      if (path === "reviews/review-1/ai/questions") return Promise.resolve({
        status: "ANSWERED", intent: "ATTACHMENT", answer: "The pinned observation records a direct path.",
        limitations: "Effective access was not evaluated.", current_snapshot_eligible: true,
        evidence: { retrieved: ["observation-1"], considered: ["observation-1"], cited: ["observation-1"], unavailable: [] },
      });
      return Promise.resolve({});
    });
    renderReview();
    fireEvent.click(await screen.findByRole("button", { name: "How was this policy attached?" }));
    expect(await screen.findByText("The pinned observation records a direct path.")).toBeInTheDocument();
    expect(screen.getByText("observation-1", { selector: ".badge" })).toBeInTheDocument();
    expect(apiFetch).toHaveBeenCalledWith("reviews/review-1/ai/questions", expect.objectContaining({
      method: "POST", body: JSON.stringify({ intent: "ATTACHMENT" }),
    }));
  });
});
