import { describe, expect, it } from "vitest";
import { defaultWorkspacePath } from "./navigation";

describe("default workspace", () => {
  it("routes users to the first workspace granted by their roles", () => {
    expect(defaultWorkspacePath(["reviewer", "campaign_admin"])).toBe("/reviews");
    expect(defaultWorkspacePath(["campaign_admin"])).toBe("/campaigns");
    expect(defaultWorkspacePath(["remediation_approver"])).toBe("/remediation");
    expect(defaultWorkspacePath(["auditor"])).toBe("/audit");
    expect(defaultWorkspacePath(["remediation_operator"])).toBe("/operations");
    expect(defaultWorkspacePath([])).toBe("/access-denied");
  });
});
