export function defaultWorkspacePath(roles: string[]): string {
  if (roles.includes("reviewer")) return "/reviews";
  if (roles.includes("campaign_admin")) return "/campaigns";
  if (roles.includes("remediation_approver")) return "/remediation";
  if (roles.includes("auditor")) return "/audit";
  if (roles.includes("remediation_operator")) return "/operations";
  return "/access-denied";
}
