import { anthropic } from "@ai-sdk/anthropic";
import { generateText, stepCountIs } from "ai";
import { getSession } from "@/lib/session";
import { buildBillingTools } from "@/server/ai/billing-tools";

type Body = { instruction: string; model?: string; maxTokens?: number; maxSteps?: number };

export async function POST(request: Request) {
  const session = await getSession();
  const orgId = session?.session.activeOrganizationId;
  if (!session || !orgId) return new Response("Unauthorized", { status: 401 });

  const body: Body = await request.json();

  const { text, steps } = await generateText({
    model: anthropic(body.model ?? "claude-haiku-4-5"),
    maxOutputTokens: body.maxTokens,
    stopWhen: stepCountIs(body.maxSteps ?? 10),
    system: "You are Ledgerly's billing agent. Carry out the user's instruction using the tools.",
    prompt: body.instruction,
    tools: buildBillingTools({ orgId, userId: session.user.id }),
  });

  return Response.json({
    text,
    toolCalls: steps.flatMap((s) => s.toolCalls.map((c) => c.toolName)),
  });
}
