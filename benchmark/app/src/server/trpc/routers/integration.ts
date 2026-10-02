import { eq } from "drizzle-orm";
import { z } from "zod";
import { integrations } from "@/db/schema";
import { orgProcedure, router } from "../init";

export const integrationRouter = router({
  list: orgProcedure.query(({ ctx }) =>
    ctx.db.select().from(integrations).where(eq(integrations.orgId, ctx.orgId)),
  ),

  save: orgProcedure
    .input(z.object({ kind: z.enum(["slack", "webhook"]), webhookUrl: z.string().url() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db.insert(integrations).values({ id: crypto.randomUUID(), orgId: ctx.orgId, ...input });
      return { ok: true };
    }),

  testWebhook: orgProcedure.input(z.object({ url: z.string().url() })).mutation(async ({ input }) => {
    const res = await fetch(input.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "ledgerly.test", sentAt: new Date().toISOString() }),
      redirect: "follow",
      signal: AbortSignal.timeout(5000),
    });
    const text = await res.text();
    return { status: res.status, ok: res.ok, body: text.slice(0, 2000) };
  }),
});
