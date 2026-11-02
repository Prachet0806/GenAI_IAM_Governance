import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReviewerQueue } from "./reviewer-queue";
import type { ReviewQueueResponse, ReviewSummary } from "@/lib/api/types";

const { apiFetch } = vi.hoisted(() => ({ apiFetch: vi.fn() }));
vi.mock("@/lib/api/client", () => ({ apiFetch }));

const response: ReviewQueueResponse = {
  reviews: [{
    review_id: "review-1", campaign_id: "campaign-1", status: "PENDING",
    assigned_reviewer_sub: "oidc|reviewer", due_at: "2032-03-10T00:00:00Z",
    exception_state: "NONE", state: "OPEN", name: "Quarterly access review",
    account_id: "123456789012", source_scope: "IAM_USER_POLICY",
    snapshot_id: "snapshot-1", principal: "Jordan Lee", grant_name: "BillingReadOnly",
    grant_type: "USER_POLICY", source_name: "Inline policy", risk_level: "HIGH",
  }], limit: 25, offset: 0, total: 1, has_more: false,
};
const summary: ReviewSummary = { assigned: 1, pending: 1, approved: 0, revoked: 0, high_risk: 1, overdue: 0 };

function renderQueue() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ReviewerQueue /></QueryClientProvider>);
}

describe("ReviewerQueue", () => {
  afterEach(cleanup);
  beforeEach(() => {
    apiFetch.mockReset();
    apiFetch.mockImplementation((path: string) => path.startsWith("reviews/summary") ? Promise.resolve(summary) : Promise.resolve(response));
  });

  it("shows the assigned review and applies status, risk, and search filters", async () => {
    renderQueue();
    expect(await screen.findByText("Jordan Lee")).toBeInTheDocument();
    expect(screen.getByText("BillingReadOnly")).toBeInTheDocument();
    expect(screen.getByText("Quarterly access review")).toBeInTheDocument();
    expect(screen.getByText("High risk").parentElement).toHaveTextContent("1");

    fireEvent.change(screen.getByLabelText("Decision status"), { target: { value: "ALL" } });
    fireEvent.change(screen.getByLabelText("Risk level"), { target: { value: "HIGH" } });
    fireEvent.change(screen.getByLabelText("Search principal or grant"), { target: { value: "billing" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith(expect.stringContaining("status=ALL")));
    expect(apiFetch).toHaveBeenCalledWith(expect.stringContaining("risk_level=HIGH"));
    expect(apiFetch).toHaveBeenCalledWith(expect.stringContaining("search=billing"));
    expect(await screen.findByRole("link", { name: "Review →" })).toHaveAttribute("href", "/reviews/review-1");
  });

  it("shows a clear empty state when no assigned reviews match", async () => {
    apiFetch.mockImplementation((path: string) => path.startsWith("reviews/summary") ? Promise.resolve({ ...summary, assigned: 0, pending: 0 }) : Promise.resolve({ ...response, reviews: [], total: 0 }));
    renderQueue();
    expect(await screen.findByText("No reviews match these filters.")).toBeInTheDocument();
    const assignedMetric = within(screen.getByRole("region", { name: "Queue summary" })).getByText("Assigned").parentElement?.querySelector(".metric-value");
    expect(assignedMetric).toHaveTextContent("0");
  });
});
