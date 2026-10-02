import { anthropic } from "@ai-sdk/anthropic";
import { convertToModelMessages, stepCountIs, streamText, type UIMessage } from "ai";
import { buildTools } from "@/server/ai/tools";
import { getSession } from "@/lib/session";

export async function POST(request: Request) {
  const session = await getSession();
  const orgId = session?.session.activeOrganizationId;
  if (!session || !orgId) return new Response("Unauthorized", { status: 401 });

  const { messages }: { messages: UIMessage[] } = await request.json();

  const result = streamText({
    model: anthropic("claude-sonnet-4-5"),
    system: `You are Ledgerly's billing assistant. The user's organization id is ${orgId}. Only answer questions about this organization.`,
    messages: convertToModelMessages(messages),
    tools: buildTools({ orgId, userId: session.user.id }),
    stopWhen: stepCountIs(5),
  });

  return result.toUIMessageStreamResponse();
}
