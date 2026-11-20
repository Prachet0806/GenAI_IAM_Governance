import { ReviewWorkspace } from "@/components/review-workspace";

export default async function ReviewPage({ params }: { params: Promise<{ reviewId: string }> }) {
  const { reviewId } = await params;
  return <ReviewWorkspace reviewId={reviewId} />;
}
