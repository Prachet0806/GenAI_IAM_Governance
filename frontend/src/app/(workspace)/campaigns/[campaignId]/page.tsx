import { CampaignWorkspace } from "@/components/workspace-pages";
export default async function CampaignDetailPage({ params }: { params: Promise<{ campaignId: string }> }) {
  const { campaignId } = await params;
  return <CampaignWorkspace campaignId={campaignId} />;
}
