import { RemediationWorkspace } from "@/components/workspace-pages";
export default async function RemediationDetailPage({ params }: { params: Promise<{ reviewId: string }> }) {
  const { reviewId } = await params;
  return <RemediationWorkspace reviewId={reviewId} />;
}
