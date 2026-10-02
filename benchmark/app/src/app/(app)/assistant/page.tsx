import { AssistantPanel } from "@/components/assistant-panel";
import { requireOrg } from "@/lib/session";

export default async function AssistantPage() {
  await requireOrg();
  return <AssistantPanel />;
}
