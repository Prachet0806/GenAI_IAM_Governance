import { AuditReviewWorkspace } from "@/components/audit-review-workspace";

export default async function AuditReviewPage({ params }: { params: Promise<{ reviewId: string }> }) {
  const { reviewId } = await params;
  return <AuditReviewWorkspace reviewId={reviewId} />;
}
