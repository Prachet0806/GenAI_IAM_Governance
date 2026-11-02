import { redirect } from "next/navigation";
import { auth } from "../../../auth";
import { WorkspaceShell } from "@/components/workspace-shell";

export default async function WorkspaceLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const session = await auth();
  if (!session?.user) redirect("/login");
  return <WorkspaceShell>{children}</WorkspaceShell>;
}
