import { LoginCard } from "@/components/login-card";

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return <LoginCard error={Boolean(error)} />;
}
