import { TRPCError } from "@trpc/server";
import { and, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { invoices } from "@/db/schema";
import { orgProcedure, router } from "../init";

export const invoiceRouter = router({
  list: orgProcedure
    .input(z.object({ status: z.enum(["draft", "open", "paid", "void"]).optional() }))
    .query(({ ctx, input }) =>
      ctx.db
        .select({
          id: invoices.id,
          number: invoices.number,
          amountCents: invoices.amountCents,
          status: invoices.status,
          dueDate: invoices.dueDate,
        })
        .from(invoices)
        .where(and(eq(invoices.orgId, ctx.orgId), input.status ? eq(invoices.status, input.status) : undefined))
        .orderBy(desc(invoices.createdAt)),
    ),

  byId: orgProcedure.input(z.object({ id: z.string() })).query(async ({ ctx, input }) => {
    const invoice = await ctx.db.query.invoices.findFirst({
      where: (i, { and, eq }) => and(eq(i.id, input.id), eq(i.orgId, ctx.orgId)),
      with: { lines: true, customer: true },
    });
    if (!invoice) throw new TRPCError({ code: "NOT_FOUND" });
    return invoice;
  }),
});
